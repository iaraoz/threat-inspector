$(function() {
  let apiKeys = { vt: "", abuse: "", phishtank: "", urlscan: "" };

  function loadKeys() {
    chrome.storage.local.get(['vtKey','abuseKey','phishKey','urlscanKey'], function(d) {
      apiKeys.vt = d.vtKey || "";
      apiKeys.abuse = d.abuseKey || "";
      apiKeys.phishtank = d.phishKey || "";
      apiKeys.urlscan = d.urlscanKey || "";
      $("#vt-key").val(apiKeys.vt);
      $("#abuseipdb-key").val(apiKeys.abuse);
      $("#phishtank-key").val(apiKeys.phishtank);
      $("#urlscan-key").val(apiKeys.urlscan);
    });
  }

  function saveKeys(e) {
    e.preventDefault();
    chrome.storage.local.set({
      vtKey: $("#vt-key").val().trim(),
      abuseKey: $("#abuseipdb-key").val().trim(),
      phishKey: $("#phishtank-key").val().trim(),
      urlscanKey: $("#urlscan-key").val().trim()
    }, function() {
      $("#settings-status").text("Saved!").addClass("text-success");
      setTimeout(()=>$("#settings-status").text(""), 1300);
      loadKeys();
    });
  }

  $("#settings-form").on("submit", saveKeys);
  loadKeys();

  $("#ioc-form").on("submit", function(e){
    e.preventDefault();
    analyzeIoc();
  });

  function detectType(ioc) {
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(ioc);
    const isUrl = /^https?:\/\//.test(ioc) || (/\./.test(ioc) && !ioc.includes("@") && !isIP && !isHash);
    const isEmail = /^[^@]+@[^@]+\.[^@]+$/.test(ioc);
    return { isIP, isHash, isUrl, isEmail };
  }

  function extractDomain(ioc) {
    try {
      if (/^https?:\/\//i.test(ioc)) {
        return (new URL(ioc)).hostname.replace(/^www\./, '');
      } else if (/\./.test(ioc)) {
        return ioc.replace(/^www\./, '');
      }
    } catch (e) { return ioc; }
    return ioc;
  }

  function analyzeIoc() {
    const ioc = $("#ioc-input").val().trim();
    if (!ioc) return;
    $("#status").html('<div class="text-center my-2"><div class="spinner-border"></div></div>');
    $("#results").html("");

    const { isIP, isHash, isUrl, isEmail } = detectType(ioc);

    let promises = [];
    if (isIP) {
      promises = [
        getAbuseIpdb(ioc),
        getVirusTotal(ioc),
        getPhishTank(ioc),
        getUrlscan(ioc),
        getJoeSandbox(ioc)
      ];
    } else if (isUrl) {
      promises = [
        getUrlscan(ioc),
        getVirusTotal(ioc),
        getPhishTank(ioc),
        getAbuseIpdb(ioc),
        getJoeSandbox(ioc)
      ];
    } else if (isHash) {
      promises = [
        getVirusTotal(ioc),
        getJoeSandbox(ioc),
        getPhishTank(ioc),
        getAbuseIpdb(ioc),
        getUrlscan(ioc)
      ];
    } else if (isEmail) {
      promises = [];
    } else {
      promises = [
        getVirusTotal(ioc),
        getPhishTank(ioc),
        getAbuseIpdb(ioc),
        getUrlscan(ioc),
        getJoeSandbox(ioc)
      ];
    }

    Promise.all(promises).then(cards => {
      $("#status").html("");
      $("#results").html(cards.filter(x=>!!x).join(""));
    }).catch(err=>{
      $("#status").html("");
      $("#results").html(`<div class="sb-card sb-card-header danger">Error: ${err.message||err}</div>`);
    });
  }

  // ---- VIRUSTOTAL ---- //
  async function getVirusTotal(ioc) {
    if (!apiKeys.vt) return '';
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(ioc);
    const isUrl = /^https?:\/\//.test(ioc) || (/\./.test(ioc) && !ioc.includes("@"));
    let url, type;
    if (isIP)      { type = "ip_address"; url = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`; }
    else if (isHash) { type = "file"; url = `https://www.virustotal.com/api/v3/files/${ioc}`; }
    else if (isUrl)  { type = "url"; 
      let enc = btoa(ioc).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      url = `https://www.virustotal.com/api/v3/urls/${enc}`;
    } else return '';
    try {
      const resp = await fetch(url, {
        headers: { "x-apikey": apiKeys.vt }
      });
      const data = await resp.json();
      if (!data || !data.data || !data.data.attributes)
        throw new Error('Not found');
      let attr = data.data.attributes;
      let stats = attr.last_analysis_stats || {};
      let badgeRow = `
        <span class="sb-badge danger fs-6 me-1">${stats.malicious || 0} malicious</span>
        <span class="sb-badge warning fs-6 me-1">${stats.suspicious || 0} suspicious</span>
        <span class="sb-badge success fs-6 me-1">${stats.harmless || 0} clean</span>
        <span class="sb-badge secondary fs-6">${stats.undetected || 0} undetected</span>
      `;
      let malwareNames = '';
      if (type === "file" && attr.names && attr.names.length) {
        malwareNames = `<div class="mb-1 mt-2" style="font-size:1em;">
          <b>File names:</b> <span class="sb-badge secondary">${escapeHTML(attr.names[0])}</span>
          ${attr.names.slice(1,7).map(n=>`<span class="sb-badge primary ms-1">${escapeHTML(n)}</span>`).join('')}
          ${attr.names.length>7 ? `<span class="sb-badge primary ms-1">+${attr.names.length-7} more</span>` : ""}
        </div>`;
      }
      let maliciousEngines = '';
      if(attr.last_analysis_results){
        const malNames = Object.values(attr.last_analysis_results)
          .filter(r => r.category==="malicious" && r.result)
          .map(r=>escapeHTML(r.result));
        if(malNames.length){
          maliciousEngines = `<div style="font-size:.98em;"><b>Malware detected:</b> 
            ${malNames.slice(0,8).map(n=>`<span class="sb-badge danger ms-1">${n}</span>`).join('')}
            ${malNames.length>8 ? `<span class="sb-badge secondary ms-1">+${malNames.length-8} more</span>` : ""}
          </div>`;
        }
      }
      return cardTemplate({
        icon: `<span class="fa-brands fa-virustotal"></span>`,
        title: "VirusTotal",
        headerClass: 'virustotal',
        content: `
          <div class="mb-2">${badgeRow}</div>
          ${malwareNames}
          ${maliciousEngines}
        `
      });
    } catch(e) {
      return cardTemplate({
        icon: `<span class="fa-brands fa-virustotal"></span>`,
        title: "VirusTotal",
        headerClass: 'virustotal',
        content: `<div>No results or API error.</div>`
      });
    }
  }

  // ---- ABUSEIPDB ---- //
  async function getAbuseIpdb(ioc) {
    if (!apiKeys.abuse) return '';
    const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(ioc);
    if (!isIP) return '';
    try {
      const resp = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90`, {
        headers: { "Key": apiKeys.abuse, "Accept": "application/json" }
      });
      const data = await resp.json();
      let d = data.data || {};
      let badge = d.abuseConfidenceScore >= 70 ? "danger" : d.abuseConfidenceScore > 30 ? "warning" : "success";
      return cardTemplate({
        icon: `<span class="fa-solid fa-shield-halved"></span>`,
        title: "AbuseIPDB",
        headerClass: 'abuseipdb',
        content: `
          <span class="sb-badge ${badge}">Score: ${d.abuseConfidenceScore || 0}</span>
          <span class="sb-badge info">${escapeHTML(d.countryCode||"")}</span>
          <div class="sb-info-small">${escapeHTML(d.isp||"")}</div>
          <div class="sb-info-small">Total reports: ${d.totalReports||0}, Last: ${escapeHTML(d.lastReportedAt||"-")}</div>
        `
      });
    } catch(e) {
      return cardTemplate({
        icon: `<span class="fa-solid fa-shield-halved"></span>`,
        title: "AbuseIPDB",
        headerClass: 'abuseipdb',
        content: `<div>No results or API error.</div>`
      });
    }
  }

  // ---- PHISHTANK ---- //
  async function getPhishTank(ioc) {
    const isUrl = /^https?:\/\//.test(ioc) || (/\./.test(ioc) && !ioc.includes("@"));
    if (!isUrl) return "";

    if (!apiKeys.phishtank) {
      return cardTemplate({
        icon: `<span class="fa-solid fa-fish"></span>`,
        title: "PhishTank",
        headerClass: 'info',
        content: `<div>Set your PhishTank API key in Settings to check this URL.</div>`
      });
    }
    try {
      const resp = await fetch("https://checkurl.phishtank.com/checkurl/", {
        method: "POST",
        headers: {"Content-Type": "application/x-www-form-urlencoded"},
        body: `url=${encodeURIComponent(ioc)}&format=json&app_key=${encodeURIComponent(apiKeys.phishtank)}`
      });
      const data = await resp.json();
      let info = data.results || {};
      if (!info.valid) {
        return cardTemplate({
          icon: `<span class="fa-solid fa-fish"></span>`,
          title: "PhishTank",
          headerClass: 'info',
          content: `<div>This URL is NOT reported as phishing in PhishTank.</div>`
        });
      }
      let verdict = info.verified ? 
        `<span class="sb-badge danger">Phishing Verified</span>` :
        `<span class="sb-badge warning">Reported, not verified</span>`;
      return cardTemplate({
        icon: `<span class="fa-solid fa-fish"></span>`,
        title: "PhishTank",
        headerClass: 'info',
        content: `<div>${verdict}<br>
          Submitted: <span class="sb-badge info">${escapeHTML(info.submission_time || "-")}</span><br>
          <span class="sb-info-small">PhishTank ID: ${info.phishtank_id || "-"}</span>
        </div>`
      });
    } catch (e) {
      return cardTemplate({
        icon: `<span class="fa-solid fa-fish"></span>`,
        title: "PhishTank",
        headerClass: 'info',
        content: `<div>Error fetching from PhishTank API.</div>`
      });
    }
  }

  // ---- URLSCAN.IO ---- //
  async function getUrlscan(ioc) {
    if (!apiKeys.urlscan) return '';
    const isUrl = /^https?:\/\//.test(ioc) || (/\./.test(ioc) && !ioc.includes("@"));
    if (!isUrl) return '';
    const domain = extractDomain(ioc); // Asegúrate que esto devuelva solo el dominio, sin barra ni "www."
    try {
      const resp = await fetch("https://urlscan.io/api/v1/search/?q=" + encodeURIComponent(domain), {
        headers: { "API-Key": apiKeys.urlscan }
      });
      const data = await resp.json();
      // Filtra resultados que tengan coincidencia exacta con el dominio ingresado
      const matching = (data.results || []).filter(r =>
        (r.page && r.page.domain && r.page.domain.replace(/^www\./, '') === domain) ||
        (r.task && r.task.domain && r.task.domain.replace(/^www\./, '') === domain)
      );
      if (!matching.length) {
        return cardTemplate({
          icon: `<i class="fa-solid fa-globe"></i>`,
          title: "urlscan.io",
          headerClass: 'urlscan',
          content: `<div class="sb-info-small">No direct scan found for this domain.</div>`
        });
      }
      // Toma el más reciente
      let first = matching[0];
      let verdict = (first.verdicts?.overall?.malicious) ? "danger" : "success";
      let pageDomain = first.page?.domain || "-";
      let scanTime = first.task?.time || "-";
      let screenshot = first.screenshot
        ? `<img src="${escapeHTML(first.screenshot)}" alt="screenshot" style="max-width:100%;margin-top:6px;border-radius:7px;">`
        : "";
      let resultUrl = first.result || "";
  
      return cardTemplate({
        icon: `<i class="fa-solid fa-globe"></i>`,
        title: "urlscan.io",
        headerClass: 'urlscan',
        content: `<div class="sb-info-small">
          Verdict: <span class="sb-badge ${verdict}">${first.verdicts?.overall?.malicious ? "Malicious" : "Clean"}</span>
          <br>Domain: ${escapeHTML(pageDomain)}
          <br>Scan: <span class="sb-badge info">${escapeHTML(scanTime)}</span>
          ${screenshot}
          <div style="margin-top:8px"><a class="sb-btn" href="${escapeHTML(resultUrl)}" target="_blank" rel="noopener">View Details</a></div>
        </div>`
      });
    } catch(e) {
      return cardTemplate({
        icon: `<i class="fa-solid fa-globe"></i>`,
        title: "urlscan.io",
        headerClass: 'urlscan',
        content: `<div>No results or API error.</div>`
      });
    }
  }
  // ---- JOE SANDBOX ---- //
  async function getJoeSandbox(ioc) {
    const isHash = /^[a-fA-F0-9]{32,64}$/.test(ioc);
    if (!isHash) return '';
    try {
      const resp = await fetch(`https://www.joesandbox.com/search?query=${encodeURIComponent(ioc)}&type=hash`);
      const html = await resp.text();
      if(html.includes("No results found") || !html.match(/href="\/analysis\/report\/[0-9a-zA-Z]+"/i)){
        return cardTemplate({
          icon: `<span class="fa-solid fa-flask"></span>`,
          title: "Joe Sandbox",
          headerClass: 'joe',
          content: `<div>No public report found for this hash.</div>`
        });
      }
      return cardTemplate({
        icon: `<span class="fa-solid fa-flask"></span>`,
        title: "Joe Sandbox",
        headerClass: 'joe',
        content: `<div class="sb-info-small">Public analysis report exists for this hash on Joe Sandbox.</div>`
      });
    } catch(e) {
      return cardTemplate({
        icon: `<span class="fa-solid fa-flask"></span>`,
        title: "Joe Sandbox",
        headerClass: 'joe',
        content: `<div>Error fetching from Joe Sandbox.</div>`
      });
    }
  }

  // ---- TEMPLATE Y XSS ---- //
  function cardTemplate({icon, title, headerClass, content}) {
    return `
    <div class="sb-card mb-3">
      <div class="sb-card-header ${headerClass || ''}">${icon} <span>${title}</span></div>
      <div class="sb-card-content">${content}</div>
    </div>`;
  }
  function escapeHTML(str) {
    return String(str || "")
      .replace(/[&<>'"]/g, tag => ({
        '&':'&amp;','<':'&lt;','>':'&gt;',"'" :'&#39;','"':'&quot;'
      })[tag]);
  }
});
