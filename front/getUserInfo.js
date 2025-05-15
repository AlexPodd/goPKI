document.getElementById('getUserInfo').addEventListener('click', async () => {
  const name = document.getElementById('name').value.trim();
  const output = document.getElementById('output');

  if (!name) {
    output.textContent = 'Error: Please enter a user name';
    output.style.color = 'red';
    return;
  }

  try {
    const response = await fetch('https://localhost:8081/api/findUserInfo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Server error');
    }

    const result = await response.json();

    output.style.color = 'black';

    output.innerHTML = `
      <strong>Serial Number:</strong> ${result.serial}<br>
      <strong>Email:</strong> ${result.email}<br>
      <strong>Status:</strong> ${result.status}<br>
      <strong>Public Key:</strong><br><pre>${result.publicKey}</pre>
    `;

    downloadFile('certificate.pem', result.certificate, 'download-cert');

  } catch (error) {
    output.textContent = `Error: ${error.message}`;
    output.style.color = 'red';
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
