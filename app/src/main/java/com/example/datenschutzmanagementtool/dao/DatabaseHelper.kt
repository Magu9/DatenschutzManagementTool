package com.example.datenschutzmanagementtool.dao

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Build
import androidx.annotation.RequiresApi
import com.example.datenschutzmanagementtool.model.User
import java.security.MessageDigest
import java.util.*
import java.util.Base64.getEncoder
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8

class DatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    // create table sql query
    private val CREATE_USER_TABLE = ("CREATE TABLE " + TABLE_USER + "("
            + COLUMN_USER_ID + " INTEGER PRIMARY KEY AUTOINCREMENT," + COLUMN_USER_NAME + " TEXT,"
            + COLUMN_USER_EMAIL + " TEXT," + COLUMN_USER_PASSWORD + " TEXT" + ")")

    // drop table sql query
    private val DROP_USER_TABLE = "DROP TABLE IF EXISTS $TABLE_USER"

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(CREATE_USER_TABLE)
    }


    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {

        //Drop User Table if exist
        db.execSQL(DROP_USER_TABLE)

        // Create tables again
        onCreate(db)

    }

    /**
     * Erstellen eines Users
     *
     * @param user
     */
    fun addUser(user: User) {
        val db = this.writableDatabase
        val encrypt = encrypt(user.password, user.email)

        val values = ContentValues()
        values.put(COLUMN_USER_NAME, user.name)
        values.put(COLUMN_USER_EMAIL, user.email)
        values.put(COLUMN_USER_PASSWORD, encrypt)

        // Inserting Row
        db.insert(TABLE_USER, null, values)
        db.close()
    }


    /**
     * Prüfen ob User mit email existiert
     *
     * @param email
     * @return true/false
     */
    fun checkUser(email: String): Boolean {

        val columns = arrayOf(COLUMN_USER_ID)
        val db = this.readableDatabase

        val selection = "$COLUMN_USER_EMAIL = ?"

        val selectionArgs = arrayOf(email)

        /**
         * SELECT user_id FROM user WHERE user_email = 'emailadresse';
         */
        val cursor = db.query(TABLE_USER, //Table to query
            columns,        //columns to return
            selection,      //columns for the WHERE clause
            selectionArgs,  //The values for the WHERE clause
            null,  //group the rows
            null,   //filter by row groups
            null)  //The sort order


        val cursorCount = cursor.count
        cursor.close()
        db.close()

        if (cursorCount > 0) {
            return true
        }

        return false
    }

    /**
     * Prüfen ob User Daten übereinstimmen und existieren
     *
     * @param email
     * @param password
     * @return true/false
     */
    fun checkUser(email: String, password: String): Boolean {

        val encrypted = encrypt(password, email)

        val columns = arrayOf(COLUMN_USER_ID)

        val db = this.readableDatabase

        val selection = "$COLUMN_USER_EMAIL = ? AND $COLUMN_USER_PASSWORD = ?"

        val selectionArgs = arrayOf(email, encrypted)

        /**
         * SELECT user_id FROM user WHERE user_email = 'emailadresse' AND user_password = 'passwort';
         */
        val cursor = db.query(TABLE_USER, //Table to query
            columns, //columns to return
            selection, //columns for the WHERE clause
            selectionArgs, //The values for the WHERE clause
            null,  //group the rows
            null, //filter by row groups
            null) //The sort order

        val cursorCount = cursor.count
        cursor.close()
        db.close()


        if (cursorCount > 0)
            return true

        return false

    }

    /**
     * Verschlüsseön des Passwortes
     */
    fun encrypt(password: String, data: String) : String {
        val key = generateKey(password)
        val c = Cipher.getInstance("AES")
        c.init(Cipher.ENCRYPT_MODE, key)
        val encVal = c.doFinal(data.toByteArray())
        val encryptedValue = android.util.Base64.encodeToString(encVal, android.util.Base64.DEFAULT)
        return encryptedValue
    }

    /**
     * Erstellen eines Schlüssels, um Passwort zu verschlüsseln
     */
    fun generateKey(password: String) : SecretKeySpec {
        var digest = MessageDigest.getInstance("SHA-256")
        val bytes = password.toByteArray(UTF_8)
        digest.update(bytes, 0, bytes.size)
        val key = digest.digest()
        val secretKeySpec = SecretKeySpec(key, "AES")
        return secretKeySpec
    }
    companion object {

        // Database Version
        private val DATABASE_VERSION = 1

        // Database Name
        private val DATABASE_NAME = "Datenschutz.db"

        // User table name
        private val TABLE_USER = "user"

        // User Table Columns names
        private val COLUMN_USER_ID = "user_id"
        private val COLUMN_USER_NAME = "user_name"
        private val COLUMN_USER_EMAIL = "user_email"
        private val COLUMN_USER_PASSWORD = "user_password"
    }
}

