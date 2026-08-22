const { EventEmitter } = require('events');

// In-process pub/sub for pushing live updates to connected browser tabs over SSE
// (see GET /api/events in server.js). One process, one bus - if this app is ever
// run clustered/multi-instance, this needs to move to a shared broker (Redis
// pub/sub, etc) instead, since events published in one process wouldn't reach
// clients connected to another.
const bus = new EventEmitter();
// One listener per connected SSE client, not a fixed handful - don't warn on that.
bus.setMaxListeners(0);

function publish(event, data) {
  bus.emit('message', { event, data });
}

module.exports = { bus, publish };
