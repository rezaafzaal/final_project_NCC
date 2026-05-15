let socket = null;

function connectWS() {
  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  socket = new WebSocket(`${protocol}://${location.host}/ws`);

  socket.onopen = () => {
    document.getElementById('ws-status').textContent = 'Connected';
    document.getElementById('ws-status').className = 'badge badge-connected';
  };

  socket.onclose = () => {
    document.getElementById('ws-status').textContent = 'Disconnected';
    document.getElementById('ws-status').className = 'badge badge-disconnected';
    setTimeout(connectWS, 3000); // auto-reconnect
  };

  socket.onmessage = (e) => {
    const event = JSON.parse(e.data);
    handleIncomingEvent(event);
  };

  socket.onerror = () => socket.close();
}
