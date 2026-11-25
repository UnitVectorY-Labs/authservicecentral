package cmd

import (
	"encoding/json/jsontext"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func databaseVersion(fingerprint, modelID string, configuration jsontext.Value) database.ConfigurationVersion {
	return database.ConfigurationVersion{Fingerprint: fingerprint, OpenFGAModelID: modelID, SchemaVersion: "1", Configuration: configuration}
}
