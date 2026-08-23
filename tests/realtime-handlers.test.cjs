const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

process.env.JWT_SECRET = 'solutionhub_secret';

const { registerSocketHandlers } = require('../socket/realtime-handlers.cjs');

class MockSocket {
  constructor(id) {
    this.id = id;
    this.data = {};
    this.handlers = new Map();
    this.emitted = [];
    this.relayed = [];
    this.joined = [];
  }

  on(event, handler) { this.handlers.set(event, handler); }
  emit(event, payload) { this.emitted.push({ event, payload }); }
  join(room) { this.joined.push(room); }
  to(target) {
    return { emit: (event, payload) => this.relayed.push({ target, event, payload }) };
  }
  async trigger(event, payload) {
    const handler = this.handlers.get(event);
    assert.ok(handler, `missing handler for ${event}`);
    return handler(payload);
  }
}

function createHarness() {
  const caller = new MockSocket('caller-socket');
  const recipientOne = { id: 'recipient-one', data: { user: { email: 'client@example.com', role: 'client', name: 'Client One' } } };
  const recipientTwo = { id: 'recipient-two', data: { user: { email: 'client@example.com', role: 'client', name: 'Client One' } } };
  const directEvents = [];
  const io = {
    sockets: {
      sockets: new Map([
        [caller.id, caller],
        [recipientOne.id, recipientOne],
        [recipientTwo.id, recipientTwo],
      ]),
      adapter: { rooms: new Map() },
    },
    to(target) {
      return { emit: (event, payload) => directEvents.push({ target, event, payload }) };
    },
  };
  const onlineUsers = {};
  const Expert = {
    findOne: async ({ email }) => email === 'expert@example.com'
      ? { email, name: 'Dr Expert', status: 'approved', field: 'General' }
      : null,
  };
  const Message = {
    find: () => ({ sort: () => ({ limit: async () => [] }) }),
    findOne: () => ({ sort: async () => null }),
    create: async (payload) => ({ ...payload, _id: 'saved-message', createdAt: new Date() }),
  };
  const Payment = {
    findOne: () => ({
      sort: async () => ({
        clientEmail: 'client@example.com',
        expertEmail: 'expert@example.com',
        status: 'paid',
        verified: true,
        createdAt: new Date(),
      }),
    }),
  };
  const addLocalOnlineUser = (email, presence) => { onlineUsers[email] = presence; };
  const removeLocalOnlineUser = () => false;
  const emitUserPresence = async () => {};
  const redisPresence = {
    setRedisPresence: async () => {},
    clearRedisPresenceSocket: async () => false,
  };

  registerSocketHandlers(
    io,
    caller,
    { Expert, Message, Payment },
    onlineUsers,
    addLocalOnlineUser,
    removeLocalOnlineUser,
    emitUserPresence,
    redisPresence
  );

  return { caller, directEvents };
}

test('offer reaches every authenticated recipient socket and includes caller name', async () => {
  const { caller, directEvents } = createHarness();
  const token = jwt.sign(
    { email: 'expert@example.com', role: 'expert', name: 'Dr Expert' },
    process.env.JWT_SECRET
  );
  await caller.trigger('authenticate', { token });

  await caller.trigger('offer', {
    room: 'client@example.com_expert@example.com',
    offer: { type: 'offer', sdp: 'test-sdp' },
    callType: 'audio',
  });

  const offers = directEvents.filter((item) => item.event === 'offer');
  assert.deepEqual(offers.map((item) => item.target).sort(), ['recipient-one', 'recipient-two']);
  assert.equal(offers[0].payload.from, 'expert@example.com');
  assert.equal(offers[0].payload.fromName, 'Dr Expert');
  assert.equal(offers[0].payload.callType, 'audio');
});

test('typing and decline events are relayed with authenticated identity', async () => {
  const { caller } = createHarness();
  const token = jwt.sign(
    { email: 'expert@example.com', role: 'expert', name: 'Dr Expert' },
    process.env.JWT_SECRET
  );
  await caller.trigger('authenticate', { token });

  const room = 'client@example.com_expert@example.com';
  await caller.trigger('typing', { room, isTyping: true });
  await caller.trigger('call-declined', { room });

  const typing = caller.relayed.find((item) => item.event === 'typing');
  assert.equal(typing.target, room);
  assert.equal(typing.payload.user, 'expert@example.com');
  assert.equal(typing.payload.isTyping, true);

  const declined = caller.relayed.find((item) => item.event === 'call-declined');
  assert.equal(declined.target, room);
  assert.equal(declined.payload.fromName, 'Dr Expert');
});

test('messages use authenticated sender identity and preserve delivery id', async () => {
  const { caller, directEvents } = createHarness();
  const token = jwt.sign(
    { email: 'expert@example.com', role: 'expert', name: 'Dr Expert' },
    process.env.JWT_SECRET
  );
  await caller.trigger('authenticate', { token });

  await caller.trigger('send_private_message', {
    room: 'client@example.com_expert@example.com',
    author: 'spoofed@example.com',
    authorRole: 'client',
    clientMessageId: 'delivery-123',
    message: 'Verified message',
  });

  const received = directEvents.find((item) => item.event === 'receive_message');
  assert.ok(received);
  assert.equal(received.target, 'client@example.com_expert@example.com');
  assert.equal(received.payload.author, 'expert@example.com');
  assert.equal(received.payload.authorRole, 'expert');
  assert.equal(received.payload.clientMessageId, 'delivery-123');
});
