package weknora

import (
	"io"
	"mime/multipart"
)

// pipeMultipartWriter streams a single-file multipart body without
// buffering the whole file in memory.
type pipeMultipartWriter struct {
	writer  *multipart.Writer
	field   string
	fname   string
	started bool
}

func newMultipartWriter(pw *io.PipeWriter, field, fname string) *pipeMultipartWriter {
	return &pipeMultipartWriter{
		writer: multipart.NewWriter(pw),
		field:  field,
		fname:  fname,
	}
}

func (p *pipeMultipartWriter) formDataContentType() string {
	return p.writer.FormDataContentType()
}

func (p *pipeMultipartWriter) writeAndClose(src io.Reader) error {
	part, err := p.writer.CreateFormFile(p.field, p.fname)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, src); err != nil {
		return err
	}
	return p.writer.Close()
}
