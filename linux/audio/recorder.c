#include <stdio.h>
#include <alsa/asoundlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
 
 
int main(int argc, char **argv)
{
	snd_pcm_t *handle;//pcm句柄
	snd_pcm_hw_params_t *params;//pcm属性
 
	//打开设备
	int r = snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE,0);
	if(r < 0)
	{
		perror("open fail");
		return -1;
	}
 
	//设置参数
	//初始化pcm属性
	snd_pcm_hw_params_alloca(&params);
	snd_pcm_hw_params_any(handle, params);
 
	//交错模式---
	snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
	//设置双声道，小端格式，16位
	snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16_LE);
	snd_pcm_hw_params_set_channels(handle, params, 2);
	//设置采样率
	int val = 44100;
	snd_pcm_hw_params_set_rate_near(handle,params,&val,0);
 
	//设在采样周期
	int  frames;
	//snd_pcm_hw_params_set_period_size_near(handle,params,(snd_pcm_uframes_t*)&frames,0);
 
	//设置好的参数回写设备
	r = snd_pcm_hw_params(handle, params);
	if(r < 0)
	{
		perror("set params fail");
		return -1;
	}
	
 
	//16--2--（一帧数据4个字节）
	//获取一个周期有多少帧数据
	snd_pcm_hw_params_get_period_size(params,(snd_pcm_uframes_t*)&frames,0);
	snd_pcm_hw_params_get_rate(params,&val,0);
	printf("frames=%d, rate=%d\n", frames, val);
	unsigned char *buffer = malloc(4*frames);
 
	//初始化网络
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));//服务器的端口号
	addr.sin_addr.s_addr = inet_addr(argv[1]);//服务器IP
 
	int ret = 0;
	while(1)
	{
		//录音---返回帧数
		ret = snd_pcm_readi(handle,buffer,frames);
		if(ret != frames)
		{
			snd_pcm_prepare(handle);
			continue;
		}
		//udp发送--
		ret = sendto(sockfd, buffer, frames*4, 0, (struct sockaddr*)&addr, sizeof(addr));
		if(ret != frames*4)
		{
			break;
		}
	}
	close(sockfd);
	//关闭
	snd_pcm_drain(handle);
	snd_pcm_close(handle);
	free(buffer);
	return 0;
}