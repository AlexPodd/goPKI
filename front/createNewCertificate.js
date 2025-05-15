import { createPKCS10 } from './pkcs10.js';

document.getElementById('submitCsr').addEventListener('click', async () => {
  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const privateKey1 = document.getElementById('privateKey').value.trim();
  const output = document.getElementById('output');

  if (!username || !email) {
    output.textContent = 'Error: enter all required fields';
    output.style.color = 'red';
    return;
  }

  try {
    // 1. Генерация CSR
    const { csr, privateKey } = await createPKCS10({
      enrollmentID: username,
      organizationUnit: 'Marketing',
      organization: 'Podushko',
      state: 'Vladimir',
      country: 'RU',
      emailID: email
    });

      document.getElementById('output').textContent = `CSR:\n${csr}\n\nNew private Key:\n${privateKey}`;

    console.log(privateKey1)
    // 2. Импорт приватного ключа
    const cryptoKey = await importPrivateKey(privateKey1);

    console.log(cryptoKey);
    // 3. Подписываем CSR как строку
    const signature = await signData(cryptoKey, csr);


    // 4. Отправка на сервер
    const response = await fetch('https://localhost:8081/api/createNewCert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        csr,
        signature: signature
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || 'Server error');
    }

    const result = await response.json();
    output.style.color = 'green';
    document.getElementById('output').textContent += `\n\nNew certificate:\n${result.certificate}`;

    downloadFile('privateKey.pem', privateKey, 'download-key');
    downloadFile('certificate.pem', result.certificate, 'download-cert');
  } catch (err) {
    output.style.color = 'red';
    output.textContent = `Error: ${err.message}`;
  }
});


function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

async function signData(privateKey, data) {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  console.log("Encoded data:", encodedData);

  const signature = await crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" }
    },
    privateKey,
    encodedData
  );

  const base64 = arrayBufferToBase64(signature);
  console.log("Base64 Signature:", base64);
  return base64;
}

async function importPrivateKey(pem) {
  // Удаляем строки заголовка и окончания
  const pemHeader = "-----BEGIN PRIVATE KEY-----";
  const pemFooter = "-----END PRIVATE KEY-----";
  const base64 = pem.replace(pemHeader, "").replace(pemFooter, "").replace(/\s/g, "");

  const binaryDer = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
}

function str2ab(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

function downloadFile(filename, content, elementId) {
  const blob = new Blob([content], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const link = document.getElementById(elementId);
  link.href = url;
  link.style.display = 'inline';
  link.download = filename;
}