package config

import (
  "os"

  "github.com/rs/zerolog/log"
  "github.com/spf13/viper"
)

// Get config
func Get[T any]() *T {
  cwd, err := os.Getwd()
  if err != nil {
    log.Fatal().Err(err).Send()
  }

  viper.AddConfigPath(cwd)
  viper.SetConfigName(os.Getenv("config"))
  viper.SetConfigType("yaml")
  viper.WatchConfig()

  if err := viper.ReadInConfig(); err != nil {
    log.Fatal().Err(err).Send()
  }

  var cfg *T

  if err := viper.Unmarshal(&cfg); err != nil {
    log.Fatal().Err(err).Send()
  }

  return cfg
}