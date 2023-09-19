import React from "react";

export default function Test() {

    return (
        <>
            <img src={process.env.PUBLIC_URL + "/image_src/check.png"}
                style={{
                    width: "20px", display: "none"
                }}
            />
            <p style={{ fontSize: "9px" }}>전송완료</p>
        </>
    );
}