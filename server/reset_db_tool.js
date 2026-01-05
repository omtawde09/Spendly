const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

db.serialize(function () {
    console.log("Cleaning database...");

    db.run("DELETE FROM transactions", function (err) {
        if (err) console.error("❌ Error clearing transactions:", err.message);
        else console.log("✅ Transactions cleared.");
    });

    db.run("DELETE FROM categories", function (err) {
        if (err) console.error("❌ Error clearing categories:", err.message);
        else console.log("✅ Categories cleared.");
    });

    db.run("DELETE FROM users", function (err) {
        if (err) console.error("❌ Error clearing users:", err.message);
        else console.log("✅ Users cleared. All logins reset.");
    });
});

db.close((err) => {
    if (err) console.error(err.message);
    else console.log('Database connection closed.');
});
