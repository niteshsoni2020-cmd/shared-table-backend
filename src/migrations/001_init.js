module.exports.up = async function up(db, mongoose) {
  // Intentionally minimal baseline migration.
  // This establishes schema_migrations collection + idempotent framework.
  // Future migrations: indexes, backfills, policy snapshots, etc.
  await db.command({ ping: 1 });
};
