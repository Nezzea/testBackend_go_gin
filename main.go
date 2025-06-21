package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type userPrivateData struct {
	ID           string    `bson:"_id,omitempty" json:"id"`
	Username     string    `bson:"username" json:"username"`
	Name         string    `bson:"name" json:"name"`
	Email        string    `bson:"email" json:"email"`
	Password     string    `bson:"password" json:"password"`
	Age          int       `bson:"age" json:"age"`
	Deleted      bool      `bson:"deleted" json:"deleted"`
	DeletedAt    time.Time `bson:"deletedAt,omitempty" json:"deletedAt,omitempty"`
	TokenVersion int       `bson:"tokenVersion" json:"tokenVersion"`
}

type userData struct {
	ID      string `bson:"_id,omitempty" json:"id"`
	Name    string `bson:"name" json:"name"`
	Email   string `bson:"email" json:"email"`
	Deleted bool   `bson:"deleted" json:"deleted"`
}

type RequestData struct {
	Username     string `bson:"username" json:"username"`
	Password     string `bson:"password" json:"password"`
	TokenVersion int    `bson:"tokenVersion" json:"tokenVersion"`
}

type BlacklistedToken struct {
	Token     string    `bson:"token" json:"token"`
	ExpiresAt time.Time `bson:"expiresAt"  json:"expiresAt"`
}

type ResetToken struct {
	Token     string    `bson:"token"`
	Username  string    `bson:"username"`
	ExpiresAt time.Time `bson:"expiresAt"`
	Used      bool      `bson:"used"`
}

var jwtGeneralSecret = []byte("geneal")
var jwtResetPasswordSecret = []byte("reset")
var mongoClient *mongo.Client

// สร้าง JWT token
func generateToken(user RequestData, jwtSecret []byte) (string, error) {
	claims := jwt.MapClaims{
		"username":     user.Username,
		"tokenVersion": user.TokenVersion,
		"exp":          time.Now().Add(time.Hour * 24).Unix(), // หมดอายุ 24 ชม.
		"iat":          time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ฟังชั่นเพื่อแปลง JWT
func parseJWT(c *gin.Context, jwtSecret []byte) (jwt.MapClaims, bool) {
	var blacklistedToken BlacklistedToken

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		c.Abort()
		return nil, false
	}

	token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenMalformed
		}
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return nil, false
	}

	collection := mongoClient.Database("testBackend").Collection("blacklist_tokens")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = collection.FindOne(ctx, bson.M{"token": authHeader}).Decode(&blacklistedToken)
	if err == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
		c.Abort()
		return nil, false
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	return claims, ok
}

// ฟังก์ชันตรวจสอบ email format
func validateEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// Middleware ตรวจสอบ JWT token
func authMiddleware(jwtSecret []byte) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := parseJWT(c, jwtSecret)
		var user userPrivateData

		if !ok || claims["username"] == nil || claims["tokenVersion"] == nil {
			fmt.Println("claims['username']: ", claims["username"])
			fmt.Println("claims['tokenVersion']: ", claims["tokenVersion"])
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		username := claims["username"].(string)
		tokenVersion := int(claims["tokenVersion"].(float64))
		userCollection := mongoClient.Database("testBackend").Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		err := userCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}
		if user.TokenVersion != tokenVersion {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been invalidated"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func connectMongo() (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB!")

	return client, nil
}

func main() {
	var err error

	mongoClient, err = connectMongo()
	if err != nil {
		panic(err)
	}
	r := gin.Default()

	auth := r.Group("/", authMiddleware(jwtGeneralSecret))
	reset := r.Group("/", authMiddleware(jwtResetPasswordSecret))

	// 1.1
	r.POST("/login", loginHandler)
	// 1.2
	auth.GET("/logout", logoutHanler)
	// 1.3
	r.POST("/register", registerHandler)
	// 2.1
	auth.GET("/getUsers", getUserHandler)
	// 2.2
	auth.GET("/user/:id", getUserByIDHandler)
	// 2.3
	auth.PUT("/user/:id", updateUserByIDHandler)
	// 2.4.1 Hard Delete
	auth.DELETE("/user/hard/:id", hardDeleteUserByIDHandler)
	// 2.4.1 Soft Delete
	auth.DELETE("/user/soft/:id", softDeleteUserByIDHandler)
	// 3.1.1
	r.POST("/requestResetPassword", requestResetPasswordHandler)
	// 3.1.2
	reset.POST("/resetPassword", resetPasswordHandler)

	// Port Running
	r.Run(":3000")
}

func loginHandler(c *gin.Context) {
	var loginData RequestData
	var user RequestData

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := collection.FindOne(ctx, bson.M{"username": loginData.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateToken(user, jwtGeneralSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

func logoutHanler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}

	// parse เพื่อดู expiry ของ token
	token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
		return jwtGeneralSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["exp"] == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
		return
	}

	expUnix := int64(claims["exp"].(float64))
	expTime := time.Unix(expUnix, 0)

	collection := mongoClient.Database("testBackend").Collection("blacklist_tokens")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = collection.InsertOne(ctx, BlacklistedToken{
		Token:     authHeader,
		ExpiresAt: expTime,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to blacklist token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func registerHandler(c *gin.Context) {
	var newUser userPrivateData
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if !validateEmail(newUser.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	soft_count, err := collection.CountDocuments(ctx, bson.M{
		"username": newUser.Username,
		"$or": []bson.M{
			{"deleted": false},
			{"deleted": bson.M{"$exists": false}},
		}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking username"})
		return
	}
	if soft_count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
		return
	}

	hard_count, err := collection.CountDocuments(ctx, bson.M{
		"username": newUser.Username,
		"deleted":  true,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking username"})
		return
	}
	if hard_count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists(But soft Delete)"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	newUser.Password = string(hashedPassword)
	newUser.Deleted = false
	newUser.DeletedAt = time.Time{}

	_, err = collection.InsertOne(ctx, newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func getUserHandler(c *gin.Context) {
	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := collection.Find(ctx, bson.M{"$or": []bson.M{
		{"deleted": false},
		{"deleted": bson.M{"$exists": false}},
	}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer cursor.Close(ctx)

	var users []userData
	if err = cursor.All(ctx, &users); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func getUserByIDHandler(c *gin.Context) {
	var user userPrivateData
	id := c.Param("id")

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// แปลง string id เป็น ObjectID
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	err = collection.FindOne(ctx, bson.M{
		"_id": objID,
		"$or": []bson.M{
			{"deleted": false},
			{"deleted": bson.M{"$exists": false}},
		}}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func updateUserByIDHandler(c *gin.Context) {
	id := c.Param("id")
	var updateData userPrivateData

	// แปลง string id เป็น ObjectID
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// สร้าง map สำหรับเก็บฟิลด์ที่จะอัปเดต
	updateFields := bson.M{}

	if updateData.Username != "" {
		updateFields["username"] = updateData.Username
	}
	if updateData.Name != "" {
		updateFields["name"] = updateData.Name
	}
	if updateData.Email != "" {
		updateFields["email"] = updateData.Email
	}
	if updateData.Age != 0 {
		updateFields["age"] = updateData.Age
	}
	if updateData.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		updateFields["password"] = string(hashedPassword)
	}

	if len(updateFields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.UpdateOne(ctx, bson.M{"_id": objID}, bson.M{"$set": updateFields})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

func hardDeleteUserByIDHandler(c *gin.Context) {
	id := c.Param("id")

	// แปลง id เป็น ObjectID
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func softDeleteUserByIDHandler(c *gin.Context) {
	id := c.Param("id")

	// แปลง id เป็น ObjectID
	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := time.Now()
	update := bson.M{
		"$set": bson.M{
			"deleted":   true,
			"deletedAt": now,
		},
	}

	result, err := collection.UpdateOne(ctx, bson.M{"_id": objID}, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User soft deleted successfully"})
}

func requestResetPasswordHandler(c *gin.Context) {
	var resetData RequestData
	var user RequestData

	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := collection.FindOne(ctx, bson.M{"username": resetData.Username}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := generateToken(user, jwtResetPasswordSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token for reset password: ": token})
}

func resetPasswordHandler(c *gin.Context) {
	var updateData userPrivateData
	claims, ok := parseJWT(c, jwtResetPasswordSecret)

	if !ok || claims["username"] == nil || claims["tokenVersion"] == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	username := claims["username"]

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updateFields := bson.M{}

	if updateData.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updateData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		updateFields["password"] = string(hashedPassword)

	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No Password!"})
		return
	}

	collection := mongoClient.Database("testBackend").Collection("users")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := collection.UpdateOne(ctx, bson.M{"username": username}, bson.M{"$set": updateFields, "$inc": bson.M{"tokenVersion": 1}})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	if result.MatchedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

// สำหรับการเก็บ Reset Token ลง DB คือ สามามารถ Reset ได้แค่ตัวล่าสุด
// func requestResetPasswordHandler(c *gin.Context) {
// 	var resetData RequestData
// 	var user RequestData

// 	if err := c.ShouldBindJSON(&resetData); err != nil || resetData.Username == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing username"})
// 		return
// 	}

// 	collection := mongoClient.Database("testBackend").Collection("users")
// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()
// 	err := collection.FindOne(ctx, bson.M{"username": resetData.Username}).Decode(&user)
// 	if err != nil {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
// 		return
// 	}

// 	// สร้าง token
// 	token, err := generateToken(user, jwtResetPasswordSecret)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
// 		return
// 	}
// 	expire := time.Now().Add(15 * time.Minute)

// 	// บันทึกลง DB
// 	tokenCollection := mongoClient.Database("testBackend").Collection("reset_tokens")
// 	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	val := bson.M{
// 		"token":     token,
// 		"username":  resetData.Username,
// 		"expiresAt": expire,
// 		"used":      false,
// 	}

// 	result, err := tokenCollection.UpdateOne(ctx, bson.M{"username": resetData.Username, "used": false}, bson.M{"$set": val})
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update reset token"})
// 		return
// 	}
// 	if result.MatchedCount == 0 {
// 		_, err = tokenCollection.InsertOne(ctx, val)
// 		if err != nil {
// 			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create reset token"})
// 			return
// 		}
// 	}

// 	c.JSON(http.StatusOK, gin.H{"message": "Reset token created", "token": token})
// }

// func resetPasswordHandler(c *gin.Context) {
// 	var req struct {
// 		Token       string `json:"token"`
// 		NewPassword string `json:"newPassword"`
// 	}
// 	var resetToken ResetToken
// 	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" || req.NewPassword == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token or new password"})
// 		return
// 	}

// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// 	defer cancel()

// 	// ตรวจสอบ token
// 	tokenCollection := mongoClient.Database("testBackend").Collection("reset_tokens")
// 	err := tokenCollection.FindOne(ctx, bson.M{"token": req.Token}).Decode(&resetToken)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid or expired token"})
// 		return
// 	}
// 	if resetToken.Used || time.Now().After(resetToken.ExpiresAt) {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Token is used or expired"})
// 		return
// 	}

// 	// เปลี่ยนรหัสผ่าน
// 	userCollection := mongoClient.Database("testBackend").Collection("users")
// 	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hashing error"})
// 		return
// 	}

// 	_, err = userCollection.UpdateOne(ctx,
// 		bson.M{"username": resetToken.Username},
// 		bson.M{
// 			"$set": bson.M{"password": string(hashedPassword)},
// 			"$inc": bson.M{"tokenVersion": 1},
// 		},
// 	)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
// 		return
// 	}

// 	// Mark token as used
// 	_, _ = tokenCollection.UpdateOne(ctx, bson.M{"token": req.Token}, bson.M{"$set": bson.M{"used": true}})

// 	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
// }
