import {Card, Button, Table, Message} from "@alifd/next"
import PageHeader from "@/components/PageHeader"
import CaptureForm from "@/pages/capture/components/captureForm";
import CaptureResult from "@/pages/capture/components/captureResult";
import {CaptureTask} from "@/services/capture";
import captureService from "@/services/capture"
import {useEffect, useState} from "react";

const submitCapture = (props, callback) => {
  const task: CaptureTask = {
    capture_host_ns: props.capture_host_ns,
    capture_duration_seconds: props.duration
  }
  if(props.capture_type == "Pod") {
    task.pod = {
      name: props.name,
      namespace: props.namespace
    }
  }
  if(props.capture_type == "Node") {
    task.node = {
      name: props.name,
    }
  }

  captureService.createCapture(task)
    .then(res => {
      Message.success('诊断提交成功')
      callback()
    })
    .catch(err => {
      Message.error(`Error when submitting diagnosis: ${err.response.data.error}`)
    })
}

export default function Capture() {
  const [captureList, setCaptureList] = useState([])
  const refreshCaptureList = () => {
    captureService.listCaptures()
      .then(res => {
        if(res == null) {
          res = []
        }
        setCaptureList(res)
        if (res.find(i => i.status == 'running')) setTimeout(refreshCaptureList, 3000)
      })
      .catch(err => {
        Message.error(`Error when fetching diagnosis: ${err.response.data.error}`)
      })
  }
  useEffect(refreshCaptureList, [])
    return (
        <div>
          <PageHeader
          title='网络抓包'
          breadcrumbs={[{name: 'Console'}, {name: '抓包'}, {name: '分布式抓包'}]}
          />
          <Card id="card-capture" title="抓包" contentHeight="auto">
              <Card.Content>
                  <CaptureForm onSubmit={(props) => submitCapture(props, refreshCaptureList)} />
              </Card.Content>
          </Card>
          <Card id="card-capture-tasks" title="抓包任务" contentHeight="auto">
            <Card.Content>
              <CaptureResult captureResult={captureList}/>
            </Card.Content>
          </Card>
        </div>
    )
}
