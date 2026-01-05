var sqlite3 = require('sqlite3').verbose();
var db = new sqlite3.Database('./server/database.sqlite');

db.serialize(function () {
    db.run("DELETE FROM transactions", function (err) {
        if (err) console.error("Error clearing transactions:", err);
        else console.log("Transactions cleared.");
    });
    db.run("DELETE FROM categories", function (err) {
        if (err) console.error("Error clearing categories:", err);
        else console.log("Categories cleared.");
    });
    db.run("DELETE FROM users", function (err) {
        if (err) console.error("Error clearing users:", err);
        else console.log("Users cleared.");
    });
});

db.close();
