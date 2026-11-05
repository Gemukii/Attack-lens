import { randomBytes } from 'node:crypto'

// Sessions only need to survive as long as this process: a restart simply logs out.
const sessionSecret = randomBytes(32).toString('hex')

export const sessionConfig = () => ({
  password: sessionSecret,
  name: 'attacklens',
  maxAge: 8 * 60 * 60,
  cookie: { httpOnly: true, sameSite: 'strict' as const, secure: false },
})
