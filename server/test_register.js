(async () => {
  try {
    const res = await fetch('http://localhost:3000/api/users/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'TSUser', email: 'tsuser@example.com', password: 'password123' })
    });
    console.log('STATUS', res.status);
    const body = await res.text();
    console.log('BODY', body);
  } catch (e) {
    console.error('ERR', e);
  }
})();