document.addEventListener('DOMContentLoaded', () => {
    const certWarning = document.getElementById('certWarning');
    // 首次加载显示证书信任提示
    certWarning.classList.remove('hidden');
    
    const fetchBtn = document.getElementById('fetchBtn');
    const downloadAllBtn = document.getElementById('downloadAllBtn');
    const getLinksBtn = document.getElementById('getLinksBtn');
    const urlInput = document.getElementById('urlInput');
    const loading = document.getElementById('loading');
    const stats = document.getElementById('stats');
    const imageCount = document.getElementById('imageCount');
    const imageResults = document.getElementById('imageResults');

    let currentImages = [];

    // 获取图片按钮点击事件
    fetchBtn.addEventListener('click', async () => {
        const url = urlInput.value.trim();
        
        if (!url) {
            alert('请输入有效的网站URL');
            return;
        }

        // 显示加载状态
        loading.classList.remove('hidden');
        stats.classList.add('hidden');
        imageResults.innerHTML = '';
        downloadAllBtn.classList.add('hidden');
        getLinksBtn.classList.add('hidden');
        currentImages = [];
        
        try {
            // 忽略证书错误
            const response = await fetch('https://192.168.10.108:8443/api/fetch-images', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url }),
                credentials: 'include'
            }).catch(err => {
                throw new Error('连接服务器失败，请检查证书是否被浏览器信任');
            });

            if (!response.ok) {
                throw new Error('获取图片失败');
            }

            const data = await response.json();
            
            if (data.images && data.images.length > 0) {
                currentImages = data.images;
                imageCount.textContent = currentImages.length;
                stats.classList.remove('hidden');
                
                data.images.forEach(imgUrl => {
                    const imgElement = document.createElement('img');
                    imgElement.src = imgUrl;
                    imgElement.alt = '爬取的图片';
                    imageResults.appendChild(imgElement);
                });

                // 显示功能按钮
                downloadAllBtn.classList.remove('hidden');
                getLinksBtn.classList.remove('hidden');
            } else {
                imageResults.innerHTML = '<p>未找到任何图片</p>';
            }
        } catch (error) {
            console.error('Error:', error);
            imageResults.innerHTML = `<p>错误: ${error.message}</p>`;
        } finally {
            loading.classList.add('hidden');
        }
    });

    // 一键下载按钮点击事件
    downloadAllBtn.addEventListener('click', async () => {
        if (currentImages.length === 0) return;
        
        try {
            loading.classList.remove('hidden');
            // 忽略证书错误
            const response = await fetch('https://192.168.10.108:8443/api/download-zip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ imageUrls: currentImages }),
                credentials: 'include'
            }).catch(err => {
                throw new Error('连接服务器失败，请检查证书是否被浏览器信任');
            });

            if (!response.ok) {
                throw new Error('生成ZIP文件失败');
            }

            // 直接使用响应流创建下载
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'website_images.zip';
            if (contentDisposition) {
                const match = contentDisposition.match(/filename="([^"]+)"/);
                if (match && match[1]) {
                    filename = match[1];
                }
            }
            
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('下载ZIP失败:', error);
            alert('下载ZIP文件时出错: ' + error.message);
        }
    });

    // 获取链接按钮点击事件
    getLinksBtn.addEventListener('click', () => {
        if (currentImages.length === 0) return;
        
        const content = currentImages.join('\n');
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = 'image_links.txt';
        link.style.display = 'none';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        URL.revokeObjectURL(url);
    });
});
