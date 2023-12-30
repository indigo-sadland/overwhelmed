package cmd

import (

	"github.com/unidoc/unioffice/color"
	"github.com/unidoc/unioffice/common/license"
	"github.com/unidoc/unioffice/document"
	"github.com/unidoc/unioffice/measurement"
	"github.com/unidoc/unioffice/schema/soo/wml"
	"strings"

)

func docOutput(wi *Whois, api string)  error {
	err := license.SetMeteredKey(api)
	if err != nil {
		return err
	}

	doc := document.New()
	defer doc.Close()

	// First Table
	{
		table := doc.AddTable()
		// width of the page
		table.Properties().SetWidthPercent(100)
		// with thick borers
		borders := table.Properties().Borders()
		borders.SetAll(wml.ST_BorderSingle, color.Auto, measurement.Zero)

		row := table.AddRow()
		cell := row.AddCell().AddParagraph().AddRun()
		cell.Properties().SetFontFamily("Times New Roman")
		cell.Properties().SetSize(14*measurement.Pixel72)
		cell.AddText("Доменное имя")
		t := row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.DomainName)


		row = table.AddRow()
		cellTwo := row.AddCell().AddParagraph().AddRun()
		cellTwo.Properties().SetFontFamily("Times New Roman")
		cellTwo.Properties().SetSize(14*measurement.Pixel72)
		cellTwo.AddText("Дата регистрации")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.RegistrationDate)

		row = table.AddRow()
		cellThree := row.AddCell().AddParagraph().AddRun()
		cellThree.Properties().SetFontFamily("Times New Roman")
		cellThree.Properties().SetSize(14*measurement.Pixel72)
		cellThree.AddText("Дата обновления")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.UpdateDate)

		row = table.AddRow()
		cellFour := row.AddCell().AddParagraph().AddRun()
		cellFour.Properties().SetFontFamily("Times New Roman")
		cellFour.Properties().SetSize(14*measurement.Pixel72)
		cellFour.AddText("Дата истечения срока действия")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.ExpireDate)

		row = table.AddRow()
		cellFive := row.AddCell().AddParagraph().AddRun()
		cellFive.Properties().SetFontFamily("Times New Roman")
		cellFive.Properties().SetSize(14*measurement.Pixel72)
		cellFive.AddText("Регистратор доменного имени")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.Registrar)

		row = table.AddRow()
		cellSix := row.AddCell().AddParagraph().AddRun()
		cellSix.Properties().SetFontFamily("Times New Roman")
		cellSix.Properties().SetSize(14*measurement.Pixel72)
		cellSix.AddText("Регистрант доменного имени")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.Registrant)

		row = table.AddRow()
		cellSeven := row.AddCell().AddParagraph().AddRun()
		cellSeven.Properties().SetFontFamily("Times New Roman")
		cellSeven.Properties().SetSize(14*measurement.Pixel72)
		cellSeven.AddText("Страна регистранта")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(wi.RegistrantCountry)

		row = table.AddRow()
		cellEight := row.AddCell().AddParagraph().AddRun()
		cellEight.Properties().SetFontFamily("Times New Roman")
		cellEight.Properties().SetSize(14*measurement.Pixel72)
		cellEight.AddText("IP-адрес")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(strings.Join(wi.IP, ", "))

		row = table.AddRow()
		cellNine := row.AddCell().AddParagraph().AddRun()
		cellNine.Properties().SetFontFamily("Times New Roman")
		cellNine.Properties().SetSize(14*measurement.Pixel72)
		cellNine.AddText("MX-запись")
		t = row.AddCell().AddParagraph().AddRun()
		t.Properties().SetFontFamily("Times New Roman")
		t.Properties().SetSize(14*measurement.Pixel72)
		t.AddText(strings.Join(wi.MXRecord, ", "))
	}

	err = doc.SaveToFile(wi.DomainName + ".docx")
	if err != nil {
		return err
	}

	return nil

}
