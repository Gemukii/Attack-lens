export default defineEventHandler(async (event) => {
  const session = await useSession(event, sessionConfig())
  await session.clear()
  return { authenticated: false }
})
