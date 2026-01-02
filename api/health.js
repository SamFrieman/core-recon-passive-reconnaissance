module.exports = (req, res) => {
  res.setHeader('Content-Type', 'application/json')
  res.status(200).send(JSON.stringify({ ok: true, now: new Date().toISOString() }))
}
module.exports = function handler(req, res) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  return res.status(200).json({ ok: true, time: new Date().toISOString() });
}
