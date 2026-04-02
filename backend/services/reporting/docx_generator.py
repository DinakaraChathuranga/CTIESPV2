#!/usr/bin/env python3
import sys, json, os, re
from docx import Document
from docx.shared import Pt, Cm, RGBColor, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

COL_DARK="262626"; COL_RED="EF4123"; COL_WHITE="FFFFFF"; COL_BLACK="000000"
COL_LIGHT="FDE8E4"; FONT_NAME="Arial"
SEV_COLORS={"CRITICAL":"EE0000","HIGH":"C05C00","MEDIUM":"B07800","LOW":"1A7A2A"}

def rgb(h):
    h=h.lstrip("#"); return RGBColor(int(h[0:2],16),int(h[2:4],16),int(h[4:6],16))

def set_cell_bg(cell,hex_color):
    tc=cell._tc; tcPr=tc.get_or_add_tcPr()
    shd=OxmlElement("w:shd"); shd.set(qn("w:val"),"clear"); shd.set(qn("w:color"),"auto"); shd.set(qn("w:fill"),hex_color.lstrip("#"))
    tcPr.append(shd)

def cell_para(cell,text,bold=False,color=None,size=9,align=WD_ALIGN_PARAGRAPH.LEFT,italic=False):
    cell.paragraphs[0].clear(); p=cell.paragraphs[0]; p.alignment=align
    run=p.add_run(text); run.font.name=FONT_NAME; run.font.size=Pt(size); run.font.bold=bold; run.font.italic=italic
    if color: run.font.color.rgb=rgb(color)
    return p

def add_section_heading(doc,text):
    p=doc.add_paragraph(); p.paragraph_format.space_before=Pt(8); p.paragraph_format.space_after=Pt(4)
    run=p.add_run(text); run.font.name=FONT_NAME; run.font.size=Pt(12); run.font.bold=True; run.font.color.rgb=rgb(COL_BLACK)
    pPr=p._p.get_or_add_pPr(); pBdr=OxmlElement("w:pBdr")
    bottom=OxmlElement("w:bottom"); bottom.set(qn("w:val"),"single"); bottom.set(qn("w:sz"),"12"); bottom.set(qn("w:space"),"1"); bottom.set(qn("w:color"),"EF4123")
    pBdr.append(bottom); pPr.append(pBdr)

def generate_docx(data,client_name,alert_number,output_path):
    doc=Document()
    for section in doc.sections:
        section.page_width=Cm(21); section.page_height=Cm(29.7)
        section.left_margin=Cm(2.54); section.right_margin=Cm(2.54)
        section.top_margin=Cm(2.54); section.bottom_margin=Cm(2.54)
    doc.styles["Normal"].font.name=FONT_NAME; doc.styles["Normal"].font.size=Pt(10)
    sev=data.get("severity","CRITICAL")

    # COVER
    ht=doc.add_table(rows=1,cols=1); ht.style="Table Grid"
    hc=ht.rows[0].cells[0]; set_cell_bg(hc,COL_DARK)
    dp=hc.paragraphs[0]; dp.alignment=WD_ALIGN_PARAGRAPH.LEFT; dp.paragraph_format.space_before=Pt(6)
    dr=dp.add_run(data.get("generated_at","")[:10]); dr.font.name=FONT_NAME; dr.font.size=Pt(8); dr.font.color.rgb=rgb("AAAAAA")
    tp=hc.add_paragraph(); tp.alignment=WD_ALIGN_PARAGRAPH.LEFT; tp.paragraph_format.space_before=Pt(16); tp.paragraph_format.space_after=Pt(4)
    tr=tp.add_run(data.get("title","Security Advisory")); tr.font.name=FONT_NAME; tr.font.size=Pt(18); tr.font.bold=True; tr.font.color.rgb=rgb(COL_WHITE)
    cvep=hc.add_paragraph(); cvep.paragraph_format.space_after=Pt(10)
    cver=cvep.add_run(data.get("cve_ids","")); cver.font.name=FONT_NAME; cver.font.size=Pt(10); cver.font.color.rgb=rgb("DDDDDD")
    doc.add_paragraph()

    mt=doc.add_table(rows=4,cols=2); mt.style="Table Grid"
    meta=[("Type",data.get("type","Security Vulnerability")),("Severity",data.get("severity_detail",sev)),
          ("Target Platforms",data.get("target_platforms","")),("Alert Number",alert_number)]
    for i,(label,value) in enumerate(meta):
        lc=mt.rows[i].cells[0]; vc=mt.rows[i].cells[1]
        lc.width=Inches(1.8); vc.width=Inches(4.5)
        cell_para(lc,label,bold=True,size=10)
        if label=="Severity":
            vc.paragraphs[0].clear(); p=vc.paragraphs[0]
            r=p.add_run(value); r.font.name=FONT_NAME; r.font.size=Pt(10); r.font.bold=True; r.font.color.rgb=rgb(SEV_COLORS.get(sev,"EE0000"))
        else:
            cell_para(vc,value,size=10)
    doc.add_page_break()

    # CONTENT
    add_section_heading(doc,"Overview"); doc.add_paragraph()
    overview=data.get("overview_table",[])
    if not overview:
        overview=[{"product":p,"severity":sev,"cve_id":data.get("cve_ids","")} for p in (data.get("affected_products") or ["Affected Product"])[:3]]
    ov=doc.add_table(rows=1+len(overview),cols=3); ov.style="Table Grid"
    hrow=ov.rows[0]; cws=[Inches(3.0),Inches(1.5),Inches(1.8)]
    for j,(cell,hdr,w) in enumerate(zip(hrow.cells,["Product","Severity","Threat"],cws)):
        cell.width=w; set_cell_bg(cell,COL_DARK); cell_para(cell,hdr,bold=True,color=COL_WHITE,size=9,align=WD_ALIGN_PARAGRAPH.CENTER)
    for i,rd in enumerate(overview):
        row=ov.rows[i+1]; bg=COL_LIGHT if i%2==0 else COL_WHITE
        pc,sc,tc=row.cells[0],row.cells[1],row.cells[2]
        pc.width=cws[0]; sc.width=cws[1]; tc.width=cws[2]
        for c in [pc,sc,tc]: set_cell_bg(c,bg)
        rs=rd.get("severity",sev)
        cell_para(pc,rd.get("product",""),bold=True,size=9)
        cell_para(sc,rs,bold=True,color=SEV_COLORS.get(rs,"EE0000"),size=9,align=WD_ALIGN_PARAGRAPH.CENTER)
        cell_para(tc,rd.get("cve_id",""),size=8,align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()

    add_section_heading(doc,"Description")
    dt=doc.add_table(rows=2,cols=1); dt.style="Table Grid"
    dh=dt.rows[0].cells[0]; set_cell_bg(dh,COL_DARK); cell_para(dh,"Description",bold=True,color=COL_WHITE,size=10,align=WD_ALIGN_PARAGRAPH.CENTER)
    dc=dt.rows[1].cells[0]; set_cell_bg(dc,"FEF9F9")
    desc=data.get("description",""); paras=[p.strip() for p in desc.split("\n\n") if p.strip()] or [desc.strip()] or ["No description."]
    first=True
    for pt in paras:
        p=dc.paragraphs[0] if first else dc.add_paragraph(); first=False
        p.paragraph_format.space_before=Pt(4); p.paragraph_format.space_after=Pt(4); p.paragraph_format.left_indent=Pt(8)
        br=p.add_run("❖  "); br.font.name=FONT_NAME; br.font.size=Pt(9); br.font.color.rgb=rgb(COL_RED)
        r=p.add_run(pt); r.font.name=FONT_NAME; r.font.size=Pt(9)
    doc.add_paragraph()

    impact=data.get("impact",[]); refs=data.get("references",[]); cn=data.get("client_note","")
    drows=[("Affected Products","products"),("Affected Versions","versions"),("Severity","severity_row"),
           ("Impact","impact"),("Attack Vector","attack_vector"),("Remediations","remediation"),("References","references")]
    if cn: drows.append((f"Note for {client_name}","client_note"))
    drows.append(("Disclaimer","disclaimer"))
    dtbl=doc.add_table(rows=len(drows),cols=2); dtbl.style="Table Grid"
    for i,(label,key) in enumerate(drows):
        lc=dtbl.rows[i].cells[0]; vc=dtbl.rows[i].cells[1]
        lc.width=Inches(1.8); vc.width=Inches(4.5)
        set_cell_bg(lc,COL_RED); set_cell_bg(vc,"FEF9F9" if i%2==0 else COL_WHITE)
        cell_para(lc,label,bold=True,color=COL_WHITE,size=9)
        if key=="products":
            cell_para(vc,", ".join(data.get("affected_products",[]) or ["N/A"]),size=9)
        elif key=="versions":
            cell_para(vc,data.get("affected_versions","Refer to vendor advisory."),size=9)
        elif key=="severity_row":
            fp=True
            for rd in overview:
                p=vc.paragraphs[0] if fp else vc.add_paragraph(); fp=False
                rs=rd.get("severity",sev)
                r1=p.add_run(rs); r1.font.name=FONT_NAME; r1.font.size=Pt(9); r1.font.bold=True; r1.font.color.rgb=rgb(SEV_COLORS.get(rs,"EE0000"))
                r2=p.add_run(f" (CVSS {data.get('cvss_score','N/A')}) — {rd.get('cve_id','')}"); r2.font.name=FONT_NAME; r2.font.size=Pt(9)
        elif key=="impact":
            fp=True
            for item in impact:
                p=vc.paragraphs[0] if fp else vc.add_paragraph(); fp=False
                p.paragraph_format.space_before=Pt(2); p.paragraph_format.space_after=Pt(2); p.paragraph_format.left_indent=Pt(10)
                br=p.add_run("• "); br.font.name=FONT_NAME; br.font.size=Pt(9)
                if " - " in item:
                    pts=item.split(" - ",1)
                    r1=p.add_run(pts[0]+" - "); r1.font.name=FONT_NAME; r1.font.size=Pt(9); r1.font.bold=True
                    r2=p.add_run(pts[1]); r2.font.name=FONT_NAME; r2.font.size=Pt(9)
                else:
                    r=p.add_run(item); r.font.name=FONT_NAME; r.font.size=Pt(9)
        elif key=="attack_vector":
            cell_para(vc,data.get("attack_vector","Network"),size=9)
        elif key=="remediation":
            cell_para(vc,data.get("remediation","Apply patches immediately."),size=9)
        elif key=="references":
            fp=True
            for ref in refs:
                p=vc.paragraphs[0] if fp else vc.add_paragraph(); fp=False
                p.paragraph_format.space_before=Pt(2); p.paragraph_format.space_after=Pt(2)
                r=p.add_run("• "+ref); r.font.name=FONT_NAME; r.font.size=Pt(8); r.font.color.rgb=rgb("0563C1")
            if not refs: cell_para(vc,"—",size=9)
        elif key=="client_note":
            p=vc.paragraphs[0]; r=p.add_run(cn); r.font.name=FONT_NAME; r.font.size=Pt(9); r.font.italic=True; r.font.color.rgb=rgb("003366")
        elif key=="disclaimer":
            disc=data.get("disclaimer","The information provided here is on an as-is basis, without warranty of any kind.")
            fp=True
            for line in [disc,"Products past End of General Support are not evaluated as part of security advisories."]:
                p=vc.paragraphs[0] if fp else vc.add_paragraph(); fp=False
                p.paragraph_format.space_before=Pt(2); p.paragraph_format.space_after=Pt(2)
                r=p.add_run("• "+line); r.font.name=FONT_NAME; r.font.size=Pt(8)

    for section in doc.sections:
        fp=section.footer; fp2=fp.paragraphs[0] if fp.paragraphs else fp.add_paragraph()
        fp2.clear(); fp2.alignment=WD_ALIGN_PARAGRAPH.CENTER
        fr=fp2.add_run(f"{alert_number}  ·  {client_name}  ·  {data.get('generated_at','')[:10]}  ·  CONFIDENTIAL")
        fr.font.name=FONT_NAME; fr.font.size=Pt(8); fr.font.color.rgb=rgb("555555")

    doc.save(output_path)
    print(f"Saved: {output_path}")

if __name__=="__main__":
    data=json.load(open(sys.argv[1])); output=sys.argv[2]
    client=sys.argv[3] if len(sys.argv)>3 else "Client"
    alert=sys.argv[4] if len(sys.argv)>4 else "MITESP-XX"
    generate_docx(data,client,alert,output)
