# 🛡️ OAuthGuard RS - DNAT Security
### Protegendo o comércio da Serra Gaúcha contra roubo de contas por OAuth

**Por André Unic | Caxias do Sul | Bug Hunter | IBM SkillsBuild**

Problema: 8 em cada 10 sites do RS que usam "Login com Google" copiado de tutorial estão com Open Redirect.

Solucao: Scanner em PT-BR que em 15 segundos testa 5 falhas criticas (OPEN_REDIRECT, MISSING_STATE, SECRET_LEAK, TOKEN_IN_URL, HTTP_CALLBACK) e ja devolve "FACA ASSIM PRA CORRIGIR" + Selo Site Seguro RS.

### Como rodar (ate no celular)
pip install -r requirements.txt
python main.py

Impacto pos-hack: Liberar gratis para 100 lojas da Serra e entregar relatorio de risco para o SEBRAE-RS.

Autor: DNAT Security - Andre Unic - Caxias do Sul
