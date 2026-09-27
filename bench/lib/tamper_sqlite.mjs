// Tamper helper fallback: edits an SQLite file with Node's built-in sqlite (newer SQLite than the base image's Python,
// needed when the schema uses functions such as octet_length()). Usage: node tamper_sqlite.mjs DB FROM TO [FROM TO ...]
import { DatabaseSync } from 'node:sqlite';
const [db, ...pairs] = process.argv.slice(2); const d = new DatabaseSync(db); let k = 0;
for (const { name } of d.prepare("select name from sqlite_master where type='table'").all()) {
  for (const { name: col } of d.prepare(`pragma table_info("${name}")`).all()) {
    for (let i = 0; i < pairs.length; i += 2) {
      try { k += d.prepare(`update "${name}" set "${col}"=replace("${col}",?,?) where typeof("${col}")='text' and instr("${col}",?)>0`).run(pairs[i], pairs[i+1], pairs[i]).changes; } catch (e) {}
    }
  }
}
try { d.exec('pragma wal_checkpoint(TRUNCATE)'); } catch (e) {}
d.close(); console.log(JSON.stringify({ rows: k }));
