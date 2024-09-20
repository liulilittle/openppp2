package io

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	mysql_driver "github.com/go-sql-driver/mysql"
	mysql "gorm.io/driver/mysql"
	gorm "gorm.io/gorm"
)

type DB struct {
	Host     string
	Port     int
	User     string
	Password string
	DbName   string

	db    *gorm.DB
	sqlDB *sql.DB
}

func (my *DB) AutoMigrate(dst ...any) error {
	db := my.db
	return db.AutoMigrate(dst...)
}

func (my *DB) LoadDB() *gorm.DB {
	return my.db
}

func (my *DB) Close() error {
	return my.sqlDB.Close()
}

func (my *DB) IsErrDuplicatedKey(err error) bool {
	// Judging by errors in the gorm framework, but may not be correct.
	if err == gorm.ErrDuplicatedKey || errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}

	// Determine whether the mysql error is that the primary key already exists, that is, the GUID data has been inserted into the table.
	if mysql_err, ok := err.(*mysql_driver.MySQLError); ok {
		if mysql_err.Number == 1062 {
			return true
		}
	}
	return false
}

func ConnectDB(
	host string,
	port int,
	user string,
	password string,
	db_name string,
	max_open_conns int,
	max_idle_conns int,
	conn_max_life_time int) (*DB, error) {

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", user, password, host, port, db_name) // "user:password@tcp(host:port)/dbname"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(max_open_conns)
	sqlDB.SetMaxIdleConns(max_idle_conns)
	sqlDB.SetConnMaxLifetime(time.Duration(conn_max_life_time) * time.Second)

	return &DB{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		DbName:   db_name,

		db:    db,
		sqlDB: sqlDB,
	}, nil
}
