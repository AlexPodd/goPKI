import { createPKCS10 } from './pkcs10.js'

document.getElementById('generate').addEventListener('click', async () => {
  const enrollmentID = document.getElementById('username').value.trim();
  const emailID = document.getElementById('email').value.trim();
  if (!enrollmentID) {
    alert('Please enter your name.');
    return;
  }

  if (!emailID) {
      alert('Please enter your email.');
      return;
    }


  const { csr, privateKey } = await createPKCS10({
    enrollmentID,
    organizationUnit: 'Marketing',
    organization: 'Podushko',
    state: 'Vladimir',
    country: 'RU',
    emailID
  });

  document.getElementById('output').textContent = `CSR:\n${csr}\n\nPrivate Key:\n${privateKey}`;

  downloadFile('csr.pem', csr, 'download-csr');
  downloadFile('privateKey.pem', privateKey, 'download-key');

  // Отправка на сервер
  try {
    const response = await fetch('https://localhost:8081/api/cert/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ csr })
    });

    if (response.ok) {
      const { certificate } = await response.json();
      document.getElementById('output').textContent += `\n\nCertificate:\n${certificate}`;

      downloadFile('certificate.pem', certificate, 'download-cert');
    } else {
      const errorText = await response.text();
      alert('Server failed to sign certificate:\n' + errorText);
    }
  } catch (error) {
    alert('Network error: ' + error.message);
  }
});



function downloadFile(filename, content, elementId) {
  const blob = new Blob([content], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const link = document.getElementById(elementId);
  link.href = url;
  link.style.display = 'inline';
  link.download = filename;
}
