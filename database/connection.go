package database

import (
	"github.com/samundra/golang/go-auth/models"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	conn, err := gorm.Open(mysql.Open("root:admin123@/jwtAuth"), &gorm.Config{})
	if err != nil {
		panic("Could not connect to the database")
	}
	DB = conn
	conn.AutoMigrate(&models.User{})
}