package cmd

import (
	"fmt"
	"os"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/app"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/authorization/compiler"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/config"
	"github.com/UnitVectorY-Labs/authservicecentral/internal/operational"
)

func loadSchema(path string) (*config.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration %s: %w", path, err)
	}
	c, err := config.Parse(b)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func Validate(args []string) error {
	op, err := operational.Parse("validate", args)
	if err != nil {
		return err
	}
	c, err := loadSchema(op.ConfigPath)
	if err != nil {
		return err
	}
	fingerprint, err := c.Fingerprint()
	if err != nil {
		return err
	}
	if _, err := compiler.Compile(c); err != nil {
		return err
	}
	if _, err := app.BuildValidator(c, nil); err != nil {
		return fmt.Errorf("validate token sources: %w", err)
	}
	fmt.Printf("valid configuration (fingerprint %s)\n", fingerprint)
	return nil
}

func Model(args []string) error {
	op, err := operational.Parse("model", args)
	if err != nil {
		return err
	}
	c, err := loadSchema(op.ConfigPath)
	if err != nil {
		return err
	}
	m, err := compiler.Compile(c)
	if err != nil {
		return err
	}
	b, err := m.JSON()
	if err != nil {
		return fmt.Errorf("encode model: %w", err)
	}
	fmt.Println(string(b))
	return nil
}
