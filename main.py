from flask import Flask, request, render_template_string
import re, requests

app = Flask(__name__)

HTML = """
<!DOCTYPE html><html><head><title>OAuthGuard RS - DNAT</title>
<style>body{font-family:monospace;background:#0a0a0a;color:#00ff88;padding:20px}.box{border:1px solid #00ff88;padding:20px;max-width:800px;margin:auto}input{width:65%;padding:12px;background:#111;color:#fff;border:1px solid #00ff88}button{padding:12px;background:#00ff88;color:#000;font-weight:bold}.alto{color:#ff4444;font-size:22px}.seguro{color:#00ff88;font-size:22px}.log{background:#111;padding:10px;margin-top:15px;font-size:12px}</style>
</head><body><div class="box">
<h1>OAuthGuard RS</h1><p>Andre Unic | Caxias do Sul | Bug Hunter | DNAT Security</p>
<form method="post"><input name="target_url" placeholder="https://sualoja.com.br" value="{{ url or '' }}" required><button>VERIFICAR (15s)</button></form>
{% if result %}<div class="log">{% for l in result.logs %}<div>> {{ l }}</div>{% endfor %}</div>
<h2 class="{{ 'seguro' if result.status=='SITE SEGURO RS' else 'alto' }}">{{ result.status }}</h2>
{% for f in result.findings %}<div style="border:1px solid #ff4444;padding:10px;margin:10px 0"><b>[{{ f.risco }}] {{ f.id }}</b><br>{{ f.desc }}<br><b>FACA ASSIM:</b> <code>{{ f.fix }}</code></div>{% endfor %}
{% if result.status == 'SITE SEGURO RS' %}<div style="border:3px dashed #00ff88;padding:15px;text-align:center">✓ SELO SITE SEGURO RS - {{ url }}</div>{% endif %}{% endif %}
</div></body></html>
"""

def scan_site(url):
    findings=[]; logs=[]
    logs.append(f"[1/5] Acessando {url}...")
    try:
        r = requests.get(url, timeout=15, headers={"User-Agent":"OAuthGuard-RS"})
        content = r.text.lower()
        logs.append("[2/5] Testando redirect_uri aberto...")
        if "redirect_uri" in content:
            findings.append({"id":"OPEN_REDIRECT","risco":"ALTO","desc":"redirect_uri sem validação - permite roubo de conta.","fix":"Valide no backend: ALLOWED_URLS"})
        logs.append("[3/5] Verificando state...")
        if "client_id" in content and "state" not in content:
            findings.append({"id":"MISSING_STATE","risco":"ALTO","desc":"Falta parametro state - vulneravel a CSRF.","fix":"Gere state aleatorio e valide no callback"})
        logs.append("[4/5] Procurando segredos no JS...")
        if re.search(r"(client_secret|api_key)[\s=:\"']+([a-zA-Z0-9_\-]{16,})", r.text):
            findings.append({"id":"SECRET_LEAK","risco":"CRITICO","desc":"Segredo exposto no front!","fix":"Mova client_secret pro backend"})
        logs.append("[5/5] Verificando token e HTTP...")
        if "access_token" in content:
            findings.append({"id":"TOKEN_IN_URL","risco":"MEDIO","desc":"Token na URL pode vazar em logs.","fix":"Use httpOnly cookie"})
        if url.startswith("http://"):
            findings.append({"id":"HTTP_CALLBACK","risco":"ALTO","desc":"Callback em HTTP","fix":"Force HTTPS"})
    except Exception as e:
        logs.append(f"Erro: {e}")
    status = "RISCO ALTO" if findings else "SITE SEGURO RS"
    return {"findings": findings, "logs": logs, "status": status}

@app.route("/", methods=["GET","POST"])
def home():
    result=None; url=None
    if request.method=="POST":
        url=request.form.get("target_url")
        result=scan_site(url)
    return render_template_string(HTML, result=result, url=url)

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
