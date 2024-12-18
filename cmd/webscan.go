package cmd

import (
	"github.com/spf13/cobra"
)

var (
	Url        string
	Listen     string
	webscanCmd = &cobra.Command{
		Use: "webscan [OPTIONS] [COMMANDS]",
		Run: func(cmd *cobra.Command, args []string) {
			if Listen != "" {
				//fmt.Println(rootCmd.Long)
				//fmt.Printf("Listennig to %v ... now \n", Listen)
				//runner.MyEngine(Listen)
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(webscanCmd)
	webscanCmd.PersistentFlags().StringVarP(&Url, "url", "u", "", "target URL/host to scan")
	webscanCmd.Flags().StringVarP(&Listen, "listen", "L", "", "url to listen, [host]:[port],if empty 127.0.0.1:port")
}
