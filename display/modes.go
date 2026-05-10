package display

// ViewMode controls the format used when printing a packet.
type ViewMode uint8

// Recognized ViewMode values.
const (
	ViewNormal       ViewMode = iota // default one-line summary
	ViewVerbose                      // -v
	ViewHex                          // -x
	ViewHexASCII                     // -X
	ViewHexLink                      // -xx
	ViewHexASCIILink                 // -XX
)

// TSMode controls how the packet timestamp is rendered.
type TSMode uint8

// Recognized TSMode values.
const (
	TSDefault  TSMode = iota // HH:MM:SS.micros
	TSNone                   // -t
	TSUnix                   // -tt
	TSDelta                  // -ttt
	TSDateTime               // -tttt
)
