#include <stdio.h>
#include <alsa/asoundlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>

void *read_wav (char *name, int *len)
{
	FILE *wavfp = fopen (name, "rb");
	if (!wavfp)
	{
		printf ("Can't open %s to read!", name);
		return NULL;
	}
	fseek (wavfp, 0, SEEK_END);
	int data_len = (ftell (wavfp) - 44) / sizeof (char);
	printf("file size:%d\n",data_len);

	char *data = (char *) malloc (sizeof (char) * data_len);
	fseek (wavfp, 44, SEEK_SET);
	fread (data, sizeof (char), data_len, wavfp);
	fclose (wavfp);
	*len = data_len;
	return data;
}

int main(int argc, char **argv)
{
	snd_pcm_t *handle;//pcm句柄
	snd_pcm_hw_params_t *params;//pcm属性
 
	//打开设备
	int r = snd_pcm_open(&handle, "default", SND_PCM_STREAM_PLAYBACK,0);
	if(r < 0)
	{
		perror("snd pcm open fail");
		return -1;
	}
	int err;
	if ((err = snd_pcm_set_params(handle,
                                  SND_PCM_FORMAT_S16_LE,
                                  SND_PCM_ACCESS_RW_INTERLEAVED,
                                  1,
                                  16000,
                                  1,
                                  500000)) < 0)
    { /* 0.5sec */
        printf("Playback open error: %s\n", snd_strerror(err));
        exit(EXIT_FAILURE);
    }
	char *data;
	int len;
	data = read_wav("./test.wav",&len);
	len = 353162;

	snd_pcm_sframes_t frames;
	snd_pcm_writei(handle, data,len/2);
	if (frames == -EPIPE)
    {
        printf("Playback underrun occurred.\n");
        snd_pcm_prepare(handle);
    }
    else if (frames < 0)
    {
        printf("snd_pcm_writei failed: %s\n", snd_strerror(frames));
        frames = snd_pcm_recover(handle, frames, 0); //Recover the stream state from an error or suspend, such as -EINT, -EPIPE and -ESTRPIPR, for next I/O.
    }
    else if (frames < len)
    {
        printf("Short write (expected %i, wrote %li)\n", len, frames);
    }
	
	printf("frame:%ld\n",frames);
	printf("play over\n");
	free(data);
	snd_pcm_drain(handle);
	snd_pcm_close(handle);


/* 	//设置参数
	//初始化pcm属性
	snd_pcm_hw_params_alloca(&params);
	snd_pcm_hw_params_any(handle, params);
 
	//交错模式---
	snd_pcm_hw_params_set_access(handle, params, SND_PCM_ACCESS_RW_INTERLEAVED);
 
	//设置双声道，小端格式，16位
	snd_pcm_hw_params_set_format(handle, params, SND_PCM_FORMAT_S16_LE);
	snd_pcm_hw_params_set_channels(handle, params, 1);
 
	//设置采样率
	int val = 16000;
	snd_pcm_hw_params_set_rate_near(handle,params,&val,0);
 
	//设在采样周期,（最好是让系统自动设置，这一步可以省略）
	int  frames; */
	//snd_pcm_hw_params_set_period_size_near(handle,params,(snd_pcm_uframes_t*)&frames,0);
 
	//设置好的参数回写设备
	/* r = snd_pcm_hw_params(handle, params);
	if(r < 0)
	{
		perror("snd pcm params fail");
		return -1;
	} */
 
 
/* 	//16--2--（一帧数据4个字节）
	//获取一个周期有多少帧数据，一个周期一个周期方式处理音频数据。
	snd_pcm_hw_params_get_period_size(params,(snd_pcm_uframes_t*)&frames,0);
	//unsigned char *buffer = malloc(4*frames);//由于双通道，16bit，每个通道2个字节，一个周期所需要的空间为4个字节*帧数
 
	char *data;
	int len;
	data = read_wav("./test.wav",&len);
	len = 353162;
	snd_pcm_writei(handle,data,len);
	printf("play over\n");
	free(data);
	// close(sockfd);
	//关闭
	snd_pcm_drain(handle);
	snd_pcm_close(handle);
	//free(buffer);
	return 0; */
}