package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gpdf-dev/gpdf"
	"github.com/gpdf-dev/gpdf/document"
	"github.com/gpdf-dev/gpdf/pdf"
	"github.com/gpdf-dev/gpdf/template"
)

// The PDF is a compact human-readable view; CSV and JSON preserve every field.
func technicalPDF(rows []findingRow, filter url.Values) ([]byte, error) {
	doc := gpdf.NewDocument(gpdf.WithPageSize(gpdf.A4), gpdf.WithMargins(document.UniformEdges(document.Mm(16))), gpdf.WithDefaultFont("Helvetica", 9))
	doc.Header(func(p *template.PageBuilder) {
		p.AutoRow(func(r *template.RowBuilder) {
			r.Col(12, func(c *template.ColBuilder) {
				c.Text("PANBOX  /  BOXSPLOIT LABS", template.FontSize(8), template.Bold(), template.TextColor(pdf.RGBHex(0x654EAB)))
			})
		})
	})
	doc.Footer(func(p *template.PageBuilder) {
		p.AutoRow(func(r *template.RowBuilder) {
			r.Col(12, func(c *template.ColBuilder) {
				c.Text("Technical export  |  Verify scope and effective severity before sharing", template.FontSize(8), template.TextColor(pdf.RGBHex(0x6A7285)))
			})
		})
	})
	page := doc.AddPage()
	page.AutoRow(func(r *template.RowBuilder) {
		r.Col(12, func(c *template.ColBuilder) {
			c.Text("PANBOX / TECHNICAL FINDINGS", template.FontSize(19), template.Bold())
		})
	})
	page.AutoRow(func(r *template.RowBuilder) {
		r.Col(12, func(c *template.ColBuilder) {
			c.Text("Generated "+time.Now().UTC().Format("2006-01-02 15:04 UTC"), template.FontSize(9))
		})
	})
	scope := []string{}
	for _, key := range []string{"repository_id", "branch", "module", "severity"} {
		if value := filter.Get(key); value != "" {
			scope = append(scope, key+"="+value)
		}
	}
	if len(scope) == 0 {
		scope = append(scope, "All permitted repositories and latest complete branch snapshots")
	}
	page.AutoRow(func(r *template.RowBuilder) {
		r.Col(12, func(c *template.ColBuilder) {
			c.Text("Scope: "+strings.Join(scope, "  |  "), template.FontSize(9))
			c.Text(fmt.Sprintf("%d findings. Raw severity is scanner output; effective severity includes reviewed recasts.", len(rows)), template.FontSize(9))
		})
	})
	table := make([][]string, 0, len(rows))
	for _, x := range rows {
		table = append(table, []string{x.Repository, x.Branch, x.Module, x.RuleID, fmt.Sprintf("%s:%d", x.Path, x.Line), x.Raw + " / " + x.Effective})
	}
	page.AutoRow(func(r *template.RowBuilder) {
		r.Col(12, func(c *template.ColBuilder) {
			c.Table([]string{"Repository", "Branch", "Module", "Rule", "Location", "Raw / Effective"}, table, template.ColumnWidths(18, 15, 12, 17, 22, 16), template.TableHeaderStyle(template.FontSize(8), template.Bold(), template.TextColor(pdf.White), template.BgColor(pdf.RGBHex(0x483584))), template.TableStripe(pdf.RGBHex(0xF0F2F9)))
		})
	})
	return doc.Generate()
}
