import { createApp } from "./app.js";
import { connectDB } from "./config/db.js";
import { validateEnv, env } from "./config/env.js";

async function bootstrap() {
  validateEnv();
  await connectDB();

  const app = createApp();
  app.listen(env.PORT, () => {
    console.log(`🚀 Server running on http://localhost:${env.PORT}`);
  });
}

bootstrap().catch((err) => {
  console.error("❌ Failed to start server:", err);
  process.exit(1);
});
