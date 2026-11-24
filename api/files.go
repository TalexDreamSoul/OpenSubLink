package api

import (
	"errors"
	"mime"
	"net/http"
	"strings"

	"sublink/services/substore"

	"github.com/gin-gonic/gin"
)

const fileUploadLimit = 1 << 20

// Files registers administrative file operations and the public download route.
func Files(r *gin.RouterGroup, public gin.IRoutes) {
	r.GET("", listFiles)
	r.POST("", createFile)
	r.DELETE("/:name", deleteFile)
	r.GET("/:name/shares", listFileShares)
	r.POST("/:name/shares", createFileShare)
	r.DELETE("/:name/shares/:token", revokeFileShare)
	public.GET("/api/v1/file-download/:name", downloadFile)
}

func listFiles(c *gin.Context) {
	client := fileClient(c)
	if client == nil {
		return
	}
	files, err := client.ListFiles(c.Request.Context())
	if writeFileError(c, err) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": files})
}

func createFile(c *gin.Context) {
	var req struct {
		Name    string  `json:"name"`
		Content *string `json:"content"`
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, fileUploadLimit)
	if err := c.ShouldBindJSON(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "File upload exceeds 1 MiB"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file upload"})
		return
	}
	if !substore.ValidFileName(req.Name) || strings.TrimSpace(req.Name) == "" || len(req.Name) > 255 || req.Content == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "A filename and text content are required"})
		return
	}
	client := fileClient(c)
	if client == nil {
		return
	}
	file, err := client.CreateTextFile(c.Request.Context(), req.Name, *req.Content)
	if !writeFileError(c, err) {
		c.JSON(http.StatusCreated, gin.H{"data": file})
	}
}

func deleteFile(c *gin.Context) {
	client, name := namedFile(c)
	if client != nil && !writeFileError(c, client.DeleteFile(c.Request.Context(), name)) {
		c.Status(http.StatusNoContent)
	}
}

func listFileShares(c *gin.Context) {
	client, name := namedFile(c)
	if client == nil {
		return
	}
	shares, err := client.ListFileShares(c.Request.Context(), name)
	if !writeFileError(c, err) {
		c.JSON(http.StatusOK, gin.H{"data": shares})
	}
}

func createFileShare(c *gin.Context) {
	client, name := namedFile(c)
	if client == nil {
		return
	}
	token, err := client.CreateFileShare(c.Request.Context(), name)
	if !writeFileError(c, err) {
		c.JSON(http.StatusCreated, gin.H{"data": gin.H{"token": token}})
	}
}

func revokeFileShare(c *gin.Context) {
	token := c.Param("token")
	if !substore.ValidFileName(token) || len(token) > 256 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid share token"})
		return
	}
	client, name := namedFile(c)
	if client != nil && !writeFileError(c, client.RevokeFileShare(c.Request.Context(), name, token)) {
		c.Status(http.StatusNoContent)
	}
}

func downloadFile(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Referrer-Policy", "no-referrer")
	client := fileClient(c)
	if client == nil {
		return
	}
	name := c.Param("name")
	body, err := client.DownloadFile(c.Request.Context(), name, c.Query("token"))
	if writeFileError(c, err) {
		return
	}
	filename := c.Query("filename")
	if !substore.ValidFileName(filename) || len(filename) > 255 {
		filename = name
	}
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename}); disposition != "" {
		c.Header("Content-Disposition", disposition)
	}
	c.Data(http.StatusOK, "text/plain; charset=utf-8", body)
}

func namedFile(c *gin.Context) (*substore.Client, string) {
	name := c.Param("name")
	if !substore.ValidFileName(name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file name"})
		return nil, ""
	}
	return fileClient(c), name
}

func fileClient(c *gin.Context) *substore.Client {
	c.Header("Cache-Control", "private, no-store")
	cfg, _ := substore.EffectiveConfig()
	client, err := substore.NewClient(cfg)
	if err != nil {
		writeFileError(c, err)
	}
	return client
}

func writeFileError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	status := http.StatusBadGateway
	if errors.Is(err, substore.ErrFileShareNotFound) {
		status = http.StatusNotFound
	} else if errors.Is(err, substore.ErrNotConfigured) || errors.Is(err, substore.ErrFileGateway) {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{"error": err.Error()})
	return true
}
