// Mock authentication service
const MOCK_USERS = [
  {
    id: '1',
    name: 'Admin User',
    email: 'admin@ulpf.com',
    password: 'admin123',
    role: 'admin',
  },
  {
    id: '2',
    name: 'John Doe',
    email: 'john@ulpf.com',
    password: 'user123',
    role: 'user',
  },
];

let registeredUsers = [...MOCK_USERS];

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const authMock = {
  async login(email, password) {
    await delay(800);
    const user = registeredUsers.find(
      (u) => u.email === email && u.password === password
    );
    if (!user) {
      throw new Error('Invalid email or password');
    }
    const { password: _, ...userWithoutPassword } = user;
    return {
      user: userWithoutPassword,
      token: `mock-jwt-token-${user.id}-${Date.now()}`,
    };
  },

  async register(name, email, password) {
    await delay(800);
    const exists = registeredUsers.find((u) => u.email === email);
    if (exists) {
      throw new Error('Email already registered');
    }
    const newUser = {
      id: String(registeredUsers.length + 1),
      name,
      email,
      password,
      role: 'user',
    };
    registeredUsers.push(newUser);
    const { password: _, ...userWithoutPassword } = newUser;
    return {
      user: userWithoutPassword,
      token: `mock-jwt-token-${newUser.id}-${Date.now()}`,
    };
  },

  async getCurrentUser(token) {
    await delay(300);
    if (!token) throw new Error('No token provided');
    const userId = token.split('-')[3];
    const user = registeredUsers.find((u) => u.id === userId);
    if (!user) throw new Error('Invalid token');
    const { password: _, ...userWithoutPassword } = user;
    return userWithoutPassword;
  },
};
