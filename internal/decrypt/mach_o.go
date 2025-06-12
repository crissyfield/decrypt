package decrypt

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unsafe"
)

const (
	// MH_MAGIC_64 is the magic number for 64-bit Mach-O binaries.
	MH_MAGIC_64 = 0xFEEDFACF

	// MH_EXECUTE is the file type for executable Mach-O binaries.
	MH_EXECUTE = 2

	// LC_ENCRYPTION_INFO_64 is the load command type for encryption info in 64-bit Mach-O binaries.
	LC_ENCRYPTION_INFO_64 = 44
)

// MachOInfo holds information about a Mach-O binary and its encryption status.
type MachOInfo struct {
	Path               string // Path to the Mach-O binary
	FileType           uint32 // Type of the Mach-O binary (e.g., MH_EXECUTE, MH_DYLIB)
	CryptCommandOffset uint64 // Offset of the LC_ENCRYPTION_INFO load command
	CryptOffset        uint32 // Offset of the encrypted range
	CryptSize          uint32 // Size of the encrypted range
	CryptID            uint32 // Encryption system ID
}

// machOHeader represents the header of a Mach-O binary.
type machOHeader struct {
	Magic        uint32  // Magic number
	CPUType      uint32  // CPU type
	CPUSubtype   uint32  // CPU subtype
	FileType     uint32  // File type
	LoadCmdCount uint32  // Number of load commands
	LoadCmdSize  uint32  // Size of load commands
	Flags        uint32  // Flags
	_            [4]byte // Padding
}

// machOLoadCmd represents a load command in a Mach-O binary.
type machOLoadCmd struct {
	Type uint32 // Command type
	Size uint32 // Size of the command
}

// machOEncryptionInfo represents the encryption info load command in a Mach-O binary.
type machOEncryptionInfo struct {
	CryptOffset uint32  // Offset of encrypted range
	CryptSize   uint32  // Size of encrypted range
	CryptID     uint32  // Encryption system ID
	_           [4]byte // Padding
}

// parseMachO parses a Mach-O binary and returns its path if valid.
func parseMachO(path string) (*MachOInfo, error) {
	// Open file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}

	defer file.Close()

	// Read header
	var h machOHeader

	err = binary.Read(file, binary.LittleEndian, &h)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, nil
		}

		return nil, fmt.Errorf("read header: %w", err)
	}

	if h.Magic != MH_MAGIC_64 {
		return nil, nil
	}

	// Read load commands
	info := &MachOInfo{
		Path:        path,
		FileType:    h.FileType,
		CryptOffset: 0,
		CryptSize:   0,
		CryptID:     0,
	}

	for i := range h.LoadCmdCount {
		// Read load command header
		var lc machOLoadCmd

		err = binary.Read(file, binary.LittleEndian, &lc)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, nil
			}

			return nil, fmt.Errorf("read load command [%d]: %w", i, err)
		}

		// Skip if not encryption info command
		if lc.Type != LC_ENCRYPTION_INFO_64 {
			// Seek to the next load command
			_, err := file.Seek(int64(lc.Size)-int64(unsafe.Sizeof(lc)), io.SeekCurrent)
			if err != nil {
				return nil, fmt.Errorf("seek to next load command: %w", err)
			}

			continue
		}

		// Read encryption info
		var ei machOEncryptionInfo

		err = binary.Read(file, binary.LittleEndian, &ei)
		if err != nil {
			if err == io.ErrUnexpectedEOF {
				return nil, nil
			}

			return nil, fmt.Errorf("read encryption info: %w", err)
		}

		// Set encryption info
		pos, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("seek to current position: %w", err)
		}

		info.CryptCommandOffset = uint64(pos) - uint64(unsafe.Sizeof(lc)+unsafe.Sizeof(ei))
		info.CryptOffset = ei.CryptOffset
		info.CryptSize = ei.CryptSize
		info.CryptID = ei.CryptID
	}

	return info, nil
}
