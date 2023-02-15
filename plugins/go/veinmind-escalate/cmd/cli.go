package main

import (
	"encoding/json"
	"fmt"
	"github.com/chaitin/libveinmind/go/pkg/vfs"
	"os"
	"strings"
	"time"

	api "github.com/chaitin/libveinmind/go"
	"github.com/chaitin/libveinmind/go/cmd"
	"github.com/chaitin/libveinmind/go/plugin"
	"github.com/chaitin/libveinmind/go/plugin/log"
	"github.com/chaitin/veinmind-common-go/service/report"
	"github.com/chaitin/veinmind-common-go/service/report/event"

	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-escalate/utils"
)

var (
	ReportService = &report.Service{}
	pluginInfo    = plugin.Manifest{
		Name:        "veinmind-escalate",
		Author:      "veinmind-team",
		Description: "detect escalation risk for image&container",
	}
	rootCmd = &cmd.Command{}
	scanCmd = &cmd.Command{
		Use:   "scan",
		Short: "scan mode",
	}
	scanImageCmd = &cmd.Command{
		Use:   "image",
		Short: "scan image escalate",
	}
	scanContainerCmd = &cmd.Command{
		Use:   "container",
		Short: "scan container escalate",
	}
	scantestCmd = &cmd.Command{
		Use: "test",
	}
)

func inSlice(slice []string, str string) bool {
	for _, value := range slice {
		if str == value {
			return true
		}
	}
	return false
}

func scanImage(c *cmd.Command, image api.Image) error {
	result := utils.ImagesScanRun(image)
	for _, result := range result {
		ReportEvent := &event.Event{
			BasicInfo: &event.BasicInfo{
				ID:         image.ID(),
				Time:       time.Now(),
				Level:      event.High,
				Source:     pluginInfo.Name,
				Object:     event.NewObject(image),
				EventType:  event.Risk,
				DetectType: event.Image,
				AlertType:  event.Escape,
			},
			DetailInfo: &event.DetailInfo{
				AlertDetail: &event.EscapeDetail{
					Target: result.Target,
					Reason: result.Reason,
					Detail: result.Detail,
				},
			},
		}
		err := ReportService.Client.Report(ReportEvent)
		if err != nil {
			log.Error(err)
			continue
		}
	}

	return nil
}

func scanContainer(c *cmd.Command, container api.Container) error {
	result := utils.ContainersScanRun(container)
	for _, result := range result {
		ReportEvent := &event.Event{
			BasicInfo: &event.BasicInfo{
				ID:         container.ID(),
				Time:       time.Now(),
				Source:     pluginInfo.Name,
				Level:      event.High,
				Object:     event.NewObject(container),
				EventType:  event.Risk,
				DetectType: event.Container,
				AlertType:  event.Escape,
			},
			DetailInfo: &event.DetailInfo{
				AlertDetail: &event.EscapeDetail{
					Target: result.Target,
					Reason: result.Reason,
					Detail: result.Detail,
				},
			},
		}
		err := ReportService.Client.Report(ReportEvent)
		if err != nil {
			log.Error(err)
			continue
		}
	}

	return nil
}

func scanTest(c *cmd.Command, container api.Container) error {
	jsonresult := make(map[string]interface{}, 0)
	fmt.Println(strings.TrimPrefix(container.ID(), "sha256:"))
	filecontent, err := vfs.Open("/var/lib/docker/containers/" + strings.TrimPrefix(container.ID(), "sha256:") + "/hostconfig.json")
	fileinfo, err := vfs.Stat("/var/lib/docker/containers/" + strings.TrimPrefix(container.ID(), "sha256:") + "/hostconfig.json")
	content := make([]byte, fileinfo.Size())
	filecontent.Read(content)
	if err != nil {
		return err
	}
	json.Unmarshal(content, &jsonresult)
	fmt.Println(jsonresult["PidMode"])
	fmt.Println(jsonresult["CapAdd"])
	return nil
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapImageCommand(scanImageCmd, scanImage), ReportService))
	scanCmd.AddCommand(report.MapReportCmd(cmd.MapContainerCommand(scanContainerCmd, scanContainer), ReportService))
	//scanCmd.AddCommand(report.MapReportCmd(cmd.MapContainerCommand(scantestCmd, scanTest), ReportService))
	scanCmd.AddCommand(scantestCmd)
	rootCmd.AddCommand(cmd.NewInfoCommand(pluginInfo))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
