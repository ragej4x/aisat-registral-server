/**
 * This script fixes any admin records that have null contact_no values.
 * Since contact_no is defined as NOT NULL in the schema, any existing records
 * created before this constraint should be updated.
 */

const mysql = require('mysql');

// Create a connection to the database
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'aisat_registral_db'
});

// Connect to the database
connection.connect(err => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  
  console.log('Connected to database');
  
  // Find admins with null contact_no
  const findQuery = "SELECT id FROM admins WHERE contact_no IS NULL OR contact_no = ''";
  
  connection.query(findQuery, (err, results) => {
    if (err) {
      console.error('Error finding admins with null contact_no:', err);
      connection.end();
      return;
    }
    
    console.log(`Found ${results.length} admin records with missing contact_no`);
    
    if (results.length === 0) {
      console.log('No fixes needed');
      connection.end();
      return;
    }
    
    // Fix the records by setting a default contact_no
    const updateQuery = "UPDATE admins SET contact_no = 'PLEASE UPDATE' WHERE contact_no IS NULL OR contact_no = ''";
    
    connection.query(updateQuery, (err, updateResult) => {
      if (err) {
        console.error('Error updating contact_no:', err);
        connection.end();
        return;
      }
      
      console.log(`Updated ${updateResult.affectedRows} admin records with default contact_no`);
      console.log('Done!');
      connection.end();
    });
  });
}); 