package storage

import (
	"log"

	"gopkg.in/redis.v3"
)

type RedisDataStorage struct {
	URL      string
	Password string
	Database int64
	client   *redis.Client
}

func NewRedisStorage() *RedisDataStorage {
	storage := &RedisDataStorage{
		URL:      "localhost:6379",
		Password: "",
		Database: 0,
	}

	return storage
}

func (r *RedisDataStorage) OpenSession() error {
	r.client = redis.NewClient(&redis.Options{
		Addr:     r.URL,
		Password: r.Password,
		DB:       r.Database,
	})

	return nil
}

func (r *RedisDataStorage) CloseSession() {
	err := r.client.Close()
	if err != nil {
		log.Println(err)
	}
}

func (r *RedisDataStorage) InsertToken(token Token) error {
	return r.client.Set(token.RefToken, token, 0).Err()
}

func (r *RedisDataStorage) TokenByRefToken(tknString string) (Token, error) {
	tkn := Token{}
	err := r.client.Get(tknString).Scan(&tkn)
	return tkn, err
}
