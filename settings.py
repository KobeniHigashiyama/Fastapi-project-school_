
from envparse import Env
env = Env()
REAL_DATABASE_URL = env.str(
    "REAL_DATABASE_URL",
    default="postgresql+asyncpg://postgres:8412@0.0.0.0:5432/postgres"
)  

TEST_DATABASE_URL = env.str(
    "TEST_DATABASE_URL",
    default="postgresql+asyncpg://postgres_test:postgres_test@0.0.0.0:5433/postgres_test")




SECRET_KEY: str = env.str("SECRET_KEY", default="secret_key")
ALGORITHM: str = env.str("ALGORITHM", default="HS256")
ACCESS_TOKEN_EXPIRE_MINUTES: int = env.int("ACCESS_TOKEN_EXPIRE_MINUTES", default=30)
