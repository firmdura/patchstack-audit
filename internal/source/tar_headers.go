package source

import (
	"archive/tar"
	"errors"
	"math"
	"strconv"
	"strings"
)

// archive/tar hides local PAX and GNU long-name/link headers inside Next. Count
// those physical headers too, while leaving interpretation and member sizes to
// archive/tar. Observation runs only during Next: after a real member header it
// stops, so a PAX size override (or GNU sparse body) cannot shift our framing.
type headerCounter struct {
	limit, count int
	active       bool
	skip         int64
	block        [512]byte
	used         int
}

func (c *headerCounter) next(offset int64) {
	c.active = true
	c.skip = (512 - offset%512) % 512 // Previous member's physical padding.
	c.used = 0
}

func (c *headerCounter) observe(data []byte) error {
	for c.active && len(data) != 0 {
		if c.skip != 0 {
			n := min(int64(len(data)), c.skip)
			c.skip -= n
			data = data[n:]
			continue
		}
		n := copy(c.block[c.used:], data)
		c.used += n
		data = data[n:]
		if c.used != len(c.block) {
			continue
		}
		c.used = 0
		if c.block == [512]byte{} {
			c.active = false // End markers are not archive entries.
			continue
		}
		c.count++
		if c.count > c.limit {
			return errLimit
		}
		switch c.block[156] {
		case tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			// Only hidden metadata bodies need raw framing. The final member's
			// effective size is resolved by archive/tar, never this observer.
			size, err := metadataSize(c.block[124:136])
			if err != nil {
				return err
			}
			if size > math.MaxInt64-511 {
				return errLimit
			}
			c.skip = size + (512-size%512)%512
		default:
			c.active = false
		}
	}
	return nil
}

// Tar size fields use octal or GNU's nonnegative base-256 representation. This
// decodes only hidden metadata lengths; archive/tar validates the whole header.
func metadataSize(field []byte) (int64, error) {
	bad := errors.New("invalid tar metadata size")
	if field[0]&0x80 != 0 {
		if field[0]&0x40 != 0 { // Negative base-256 size.
			return 0, bad
		}
		var size int64
		for i, value := range field {
			if i == 0 {
				value &= 0x7f
			}
			if size > (math.MaxInt64-int64(value))/256 {
				return 0, bad
			}
			size = size*256 + int64(value)
		}
		return size, nil
	}
	value := strings.Trim(string(field), " \x00")
	if value == "" {
		return 0, nil
	}
	size, err := strconv.ParseUint(value, 8, 63)
	if err != nil {
		return 0, bad
	}
	return int64(size), nil
}
