package cmd

import (
	"encoding/json"

	"github.com/UnitVectorY-Labs/authservicecentral/internal/database"
)

func databaseVersion(fingerprint, modelID string, configuration json.RawMessage) database.ConfigurationVersion {
	return database.ConfigurationVersion{Fingerprint: fingerprint, OpenFGAModelID: modelID, SchemaVersion: "1", Configuration: configuration}
}
