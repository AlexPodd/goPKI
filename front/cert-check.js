document.getElementById('check').addEventListener('click', async () => {
  const serial = document.getElementById('serial').value.trim();
  const output = document.getElementById('output');

  if (!serial) {
    output.textContent = 'Error: Please enter a serial number';
    return;
  }

  try {
    const response = await fetch('https://localhost:8081/api/ocsp-request/serial', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serial })
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(errorText || 'Server error');
    }

    const result = await response.json();

    output.innerHTML = `
      <strong>Serial Number:</strong> ${result.serial}<br>
      <strong>OCSP Status:</strong> ${result.OCSP}<br>
      <strong>Checked at:</strong> ${result.timestamp}
    `;

    // Дополнительная стилизация в зависимости от статуса
    if (result.OCSP === "good") {
      output.style.color = 'green';
    } else if (result.OCSP === "revoked") {
      output.style.color = 'red';
    } else {
      output.style.color = 'black'; // или другой цвет по умолчанию
    }
  } catch (error) {
    output.textContent = `Error: ${error.message}`;
    output.style.color = 'red';
  }
});