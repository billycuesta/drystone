package ui

import (
	"fmt"
)

// PrintBanner prints the Drystone banner (shannon/gemini-cli style)
func PrintBanner() {
	banner := `
   ___            _               _
  | _ \_ _ _  _  /_\ |_ ___  _ _ ___| |)
  |  _/| '_| || |/ _ \| '_/ _ \| ' / -_)
  |_| |_|  \_, /\___/|_| \___/|_||_\___|
            |__/

  AWS Security Audit CLI powered by Claude
  ══════════════════════════════════════════
`
	fmt.Print(banner)
}

// PrintSectionHeader prints a section header
func PrintSectionHeader(title string) {
	fmt.Printf("\n📋 %s\n", title)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// PrintStep prints a numbered step
func PrintStep(number int, title string) {
	fmt.Printf("\n%d️⃣  %s\n", number, title)
}

// PrintSuccess prints a success message
func PrintSuccess(msg string) {
	fmt.Printf("✅ %s\n", msg)
}

// PrintInfo prints an info message
func PrintInfo(msg string) {
	fmt.Printf("ℹ️  %s\n", msg)
}

// PrintWarning prints a warning message
func PrintWarning(msg string) {
	fmt.Printf("⚠️  %s\n", msg)
}

// PrintReady prints the ready message
func PrintReady() {
	fmt.Println("\n▶ Iniciando auditoría de seguridad...\n")
}
