"""Gera RELATORIO.pdf a partir de relatorio/relatorio.html (Chromium via Playwright).

Uso: python3 relatorio/gerar_pdf.py
"""
from pathlib import Path
from playwright.sync_api import sync_playwright

aqui = Path(__file__).resolve().parent
html = aqui / "relatorio.html"
saida = aqui.parent / "RELATORIO.pdf"

with sync_playwright() as p:
    navegador = p.chromium.launch()
    pagina = navegador.new_page()
    pagina.goto(html.as_uri())
    pagina.wait_for_load_state("networkidle")
    pagina.pdf(path=str(saida), prefer_css_page_size=True, print_background=True)
    navegador.close()

print(f"PDF gerado: {saida}")
