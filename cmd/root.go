package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	Webscan string
	rootCmd = &cobra.Command{
		Use:   "Guts",
		Short: "Guts是一款基于nuclei引擎的被动漏洞扫描工具",
		Long: "\n     ________        __ \n" +
			"    /  _____/ __ ___/  |_  ______ \n" +
			"   /   \\  ___|  |  \\   __\\/  ___/ \n" +
			"   \\    \\_\\  \\  |  /|  |  \\___ \\\n" +
			"    \\______  /____/ |__| /____  > \n" +
			"	   \\/                 \\/ \n" +
			"                      By: Doppelg@nger \n" +
			"Guts—— 一款轻量化、低流量的被动漏洞扫描工具，兼容nuclei所有poc，支持自定义poc",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(cmd.Long)
		},
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

}
