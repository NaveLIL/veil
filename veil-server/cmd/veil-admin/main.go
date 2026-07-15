package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
)

const defaultEnrollmentURL = "https://veil.erez.pro/enroll"

const inviteCreateHelp = `Usage:
  veil-admin invite create --count N --expires DURATION [--base-url HTTPS_URL]

Creates cryptographically random, single-use Node Access enrollment links.
Each link authorizes creation of exactly one new account identity. Once that
identity is registered, its later sign-ins do not require an invite; presenting
an unused invite for an existing identity does not consume that invite.

Bearer tokens are printed exactly once, on stdout, inside URL fragments.
Redirect stdout to a mode-0600 file and distribute each line privately.
`

type createInviteOptions struct {
	count    int
	lifetime time.Duration
	baseURL  string
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "veil-admin:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if helpRequested(args) {
		_, err := io.WriteString(stdout, inviteCreateHelp)
		return err
	}
	options, err := parseCreateInviteOptions(args)
	if err != nil {
		return err
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	database, err := db.Connect(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer database.Close()

	invites, err := database.CreateNodeAccessInvites(ctx, options.count, options.lifetime)
	if err != nil {
		return err
	}
	defer func() {
		for i := range invites {
			clear(invites[i].Token)
		}
	}()

	// Every bearer token appears exactly once on stdout, inside an HTTPS URL
	// fragment. Do not add the token to diagnostics, application logs, or the
	// URL query where it would be sent to the enrollment web server.
	for i := range invites {
		enrollmentURL, err := buildEnrollmentURL(options.baseURL, invites[i].Token)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(stdout, enrollmentURL+"\n"); err != nil {
			return fmt.Errorf("write one-time invite output: %w", err)
		}
	}
	return nil
}

func helpRequested(args []string) bool {
	for _, argument := range args {
		if argument == "-h" || argument == "--help" {
			return true
		}
	}
	return false
}

func parseCreateInviteOptions(args []string) (createInviteOptions, error) {
	if len(args) < 2 || args[0] != "invite" || args[1] != "create" {
		return createInviteOptions{}, errors.New("usage: veil-admin invite create --count N --expires DURATION [--base-url HTTPS_URL] (use --help for details)")
	}
	flags := flag.NewFlagSet("invite create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	count := flags.Int("count", 1, "number of one-time invitations")
	lifetime := flags.Duration("expires", 7*24*time.Hour, "invitation lifetime")
	baseURL := flags.String("base-url", defaultEnrollmentURL, "public HTTPS enrollment page")
	if err := flags.Parse(args[2:]); err != nil {
		return createInviteOptions{}, err
	}
	if flags.NArg() != 0 {
		return createInviteOptions{}, errors.New("unexpected positional argument")
	}
	if *count < 1 || *count > db.MaxNodeAccessInviteBatch {
		return createInviteOptions{}, db.ErrNodeAccessInviteCount
	}
	if *lifetime < time.Microsecond {
		return createInviteOptions{}, db.ErrNodeAccessInviteExpiry
	}
	if _, err := buildEnrollmentURL(*baseURL, make([]byte, db.NodeAccessInviteTokenSize)); err != nil {
		return createInviteOptions{}, err
	}
	return createInviteOptions{count: *count, lifetime: *lifetime, baseURL: *baseURL}, nil
}

func buildEnrollmentURL(baseURL string, token []byte) (string, error) {
	if len(token) != db.NodeAccessInviteTokenSize {
		return "", db.ErrNodeAccessInviteInvalid
	}
	if strings.TrimSpace(baseURL) != baseURL || strings.Contains(baseURL, "#") {
		return "", errors.New("base URL must be a canonical absolute HTTPS /enroll URL without credentials, query, or fragment")
	}
	parsed, err := url.ParseRequestURI(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "/enroll" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("base URL must be a canonical absolute HTTPS /enroll URL without credentials, query, or fragment")
	}
	code := base64.RawURLEncoding.EncodeToString(token)
	parsed.Fragment = "invite=" + code
	return parsed.String(), nil
}
