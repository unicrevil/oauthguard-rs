# OAuthGuard RS - DNAT Security
Por Andre Unic - Caxias do Sul - Bug Hunter Caxias do Sul - IBM SkillsBuild

Problema: 8 em 10 sites RS com Login com Google tem Open Redirect.
Solucao: Scanner que em 15s testa 5 falhas criticas de OAuth e devolve em PT-BR "FACA ASSIM" + Selo Site Seguro RS.

Rodar:
pip install -r requirements.txt
python main.py
# abre http://localhost:8000
