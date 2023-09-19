import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { isLogined } from '../Routes/User/Login';
import Cookies from 'universal-cookie';

const dragActiveStyle = {
    color: "white",
    fontSize: "2em",
    padding: "7.67em 0",
    letterSpacing: "0",
    position: "absolute",
    textAlign: "center",
    width: "79.8%",
    background: "black",
    opacity: "0.7",
    borderRadius: "1.93em",
    zIndex: "9999",
    overflow: 'hidden'
}

const baseStyle = {
    marginTop: '5%',
    marginLeft: '10%',
    width: '80%',
    height: '34em',
    textAlign: 'center',
    border: '3px gray dashed',
    overflow: 'hidden',
    background: '#E8EDED',
    borderRadius: '4.5em'
}

function DragAndDrop() {

    const navigate = useNavigate();
    const imageToAI = () => {
        navigate("/result");
    }
    const cookies = new Cookies();

    const [imgBase64, setImgBase64] = useState();

    const onDrop = useCallback(async acceptedFiles => {


        //이미지 Base64 변환
        const file = acceptedFiles.find(f => f)
        let reader = new FileReader()

        reader.readAsDataURL(file);
        reader.onload = () => {
            setImgBase64(reader.result);

            if (!isLogined()) {
                // 비로그인 유저 IP 조회
                axios.get("https://api.ipify.org/?format=json")
                    .then((res) => {
                        // db 해당 IP 조회
                        axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:8080/issignedin', {
                            visitUserIp: res.data.ip,
                            usedCount: 1,
                        }).then((res) => {
                            if (res.data.result === 2) {
                                alert("비로그인으로 이용할 경우 사용 횟수 3회로 제한됩니다. \n");
                            } else if (res.data.result === 999) {
                                setImgBase64(res.data.result)
                                alert("오늘 사용가능한 횟수를 모두 소진하셨습니다.");
                            }
                        }).catch((e) => {
                            console.error(e)
                        })
                    })
            }
        }
    }, []);

    useEffect(() => {

        if (imgBase64 == 999) {
            console.log("page dㅣ동하면 안됨")
        } else if (imgBase64 != null) {
            sessionStorage.setItem("uploadedImg", imgBase64);

            axios.post('http://ec2-43-200-216-202.ap-northeast-2.compute.amazonaws.com:80/upload', {
                file: imgBase64
            }).then((res) => {

                let data = res.data.top
                imageToAI();

            }).catch((e) => {
                console.error(e);
            })
        }
    }, [imgBase64])

    const {
        getRootProps,
        getInputProps,
        open,
        isDragActive,
        isDragAccept,
        isDragReject
    } = useDropzone({
        onDrop,
        multiple: false,
        accept: 'image/png, image/jpeg, image/jpg',
        noClick: true,
        noKeyboard: true
    }, []);

    const style = useMemo(() => ({
        ...baseStyle,
    }), [
        isDragActive, isDragAccept, isDragReject
    ]);

    return (
        <>
            {isDragAccept ?
                <>
                    <div>
                        <div {...getRootProps({ className: 'dropzone', style })} >
                            <input {...getInputProps()} />

                            <div style={dragActiveStyle}>여기에 파일을 놔주세요.</div>
                            <div style={{
                                marginTop: "1.5em",
                                fontSize: "2rem"
                            }}>
                                <img src={process.env.PUBLIC_URL + "/image_src/icon_clothes_mainpage.png"}
                                    style={{ width: "3rem", height: "5.3rem" }} />
                                &nbsp;&nbsp;비슷한 옷을 찾아 드릴게요!
                            </div>

                            <p style={{
                                marginTop: "3%",
                                fontSize: "1.1rem"
                            }}>버튼으로 업로드
                            </p>
                            <button type="button" onClick={open}
                                style={{
                                    marginTop: "-0.8%",
                                    background: "none",
                                    border: "none"
                                }}>
                                <img src={process.env.PUBLIC_URL + "/image_src/images.png"}
                                    style={{
                                        width: "11rem",
                                        background: "none",
                                        borderRadius: "1.25rem",
                                        boxShadow: "-1px 3px 3px 0 rgba(80, 80, 80, 0.698)",
                                    }} />
                            </button>
                            <p style={{ marginTop: "1.3em" }}>또는 여기에 이미지를 드롭해주세요.</p>
                        </div>
                    </div>

                </> :
                <div>
                    <div {...getRootProps({ className: 'dropzone', style })}>
                        <input {...getInputProps()} />

                        <div style={{ display: "none" }}>여기에 파일을 놔주세요.</div>

                        <div style={{
                            marginTop: "1.5em",
                            fontSize: "2rem"
                        }}>
                            <img src={process.env.PUBLIC_URL + "/image_src/icon_clothes_mainpage.png"}
                                style={{ width: "3rem", height: "5.3rem" }} />
                            &nbsp;&nbsp;비슷한 옷을 찾아 드릴게요!
                        </div>
                        <p style={{
                            marginTop: "3%",
                            fontSize: "1.1rem"
                        }}>버튼으로 업로드
                        </p>
                        <button type="button" onClick={open}
                            style={{
                                marginTop: "-0.8%",
                                background: "none",
                                border: "none"
                            }}>
                            <img src={process.env.PUBLIC_URL + "/image_src/images.png"}
                                style={{
                                    width: "11rem",
                                    background: "none",
                                    borderRadius: "1.25rem",
                                    boxShadow: "-1px 3px 3px 0 rgba(80, 80, 80, 0.698)",
                                }} />
                        </button>
                        <p style={{ marginTop: "1.3em" }}>또는 여기에 이미지를 드롭해주세요.</p>
                    </div>
                    <div>

                    </div>
                </div>
            }
        </>
    );
}

export default DragAndDrop;